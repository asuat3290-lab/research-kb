from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import Settings
from .checkpoint import (
    CHECKPOINT_SCHEMA,
    CHECKPOINT_VERSION,
    is_standard_checkpoint_payload,
)
from .db import SCHEMA_VERSION, audit, connect, migrate, transaction
from .search import excerpt_from_original, fts_match_query
from .policy import (
    Actor,
    PolicyError,
    bounded_int,
    enforce_session_quota,
    require_admin,
    validate_query,
    validate_text,
)
from .writing_policy import (
    COMPRESSION_REVIEW_STATUSES,
    resolve_submission_policy,
    validate_writing_audit_summary,
)


EPISTEMIC_STATUSES = {
    "source_fact",
    "source_interpretation",
    "analytical_inference",
    "exploratory_hypothesis",
    "cross_source_synthesis",
    "cross_domain_analogy",
    "counterevidence",
    "open_question",
    "unresolved",
}

NOTE_PURPOSES = frozenset({"research_note", "checkpoint"})


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _context_cursor(project_id: str, offset: int) -> str:
    payload = {"kind": "research_context_index", "project_id": project_id, "offset": int(offset)}
    encoded = base64.urlsafe_b64encode(_json(payload).encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _decode_context_cursor(cursor: str, project_id: str) -> int:
    if not isinstance(cursor, str) or not cursor or len(cursor) > 512:
        raise PolicyError("invalid context cursor")
    try:
        padded = cursor + ("=" * (-len(cursor) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, base64.binascii.Error) as exc:
        raise PolicyError("invalid context cursor") from exc
    if not isinstance(payload, dict) or payload.get("kind") != "research_context_index":
        raise PolicyError("invalid context cursor")
    if payload.get("project_id") != project_id:
        raise PolicyError("cursor is outside project scope")
    offset = payload.get("offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset > 1_000_000:
        raise PolicyError("invalid context cursor")
    return offset


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


_BIBLIOGRAPHIC_FIELDS = {
    "journal_article": (
        "authors", "title", "container_title", "year", "volume", "issue",
        "page_range", "doi", "publisher",
    ),
    "book": (
        "authors", "editors", "translators", "title", "edition", "place",
        "publisher", "year", "isbn",
    ),
}


def _unknown_if_empty(value: Any) -> Any:
    if value is None or value == "":
        return "unknown"
    if isinstance(value, (list, tuple)) and not value:
        return "unknown"
    return value


def _bibliographic_profile(row: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    """Build a citation record from explicit metadata only.

    The legacy document columns remain the source for the legacy response fields.
    The structured record is deliberately whitelist-based: it never uses a file
    name, source URI, or local path as bibliographic evidence.
    """

    raw = metadata.get("bibliographic_profile")
    if not isinstance(raw, dict):
        raw = {}
    source_type = _unknown_if_empty(row["source_type"])
    fields = _BIBLIOGRAPHIC_FIELDS.get(source_type, ())
    profile: dict[str, Any] = {
        "source_type": source_type,
        "document_id": _unknown_if_empty(row["document_id"]),
        "content_hash": _unknown_if_empty(row["content_hash"]),
        "source_version": _unknown_if_empty(row["source_version"]),
    }
    for field in fields:
        profile[field] = _unknown_if_empty(raw.get(field, "unknown"))
    return profile


def _citation_locator(row: Any, *, passage_id: str | None = None, location: Any = None) -> dict[str, Any]:
    if location is None:
        location = "document"
    page: Any = "unknown"
    if isinstance(location, dict):
        page = location.get("page", location.get("page_number", "unknown"))
    return {
        "page": _unknown_if_empty(page),
        "location": _unknown_if_empty(location),
        "document_id": _unknown_if_empty(row["document_id"]),
        "passage_id": _unknown_if_empty(passage_id),
        "source_version": _unknown_if_empty(row["source_version"]),
    }


class ResearchService:
    def __init__(self, settings: Settings, actor: Actor):
        self.settings = settings
        self.actor = actor

    def initialize(self) -> None:
        migrate(self.settings)

    def _touch_session(self, connection, project_id: str | None = None) -> None:
        existing = connection.execute(
            "SELECT actor_id, project_id FROM agent_sessions WHERE session_id = ?",
            (self.actor.session_id,),
        ).fetchone()
        if existing and existing["actor_id"] != self.actor.actor_id:
            raise PolicyError("session is bound to another actor")
        if (
            existing
            and project_id
            and existing["project_id"]
            and existing["project_id"] != project_id
        ):
            raise PolicyError("session is bound to another project")
        connection.execute(
            """
            INSERT INTO agent_sessions(
                session_id, actor_id, framework, model, project_id, started_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(session_id) DO UPDATE SET
                last_seen_at = datetime('now'),
                project_id = COALESCE(agent_sessions.project_id, excluded.project_id)
            """,
            (
                self.actor.session_id,
                self.actor.actor_id,
                self.actor.framework,
                self.actor.model,
                project_id,
            ),
        )

    @staticmethod
    def _require_project(connection, project_id: str) -> None:
        found = connection.execute(
            "SELECT 1 FROM projects WHERE project_id = ? AND status = 'active'", (project_id,)
        ).fetchone()
        if not found:
            raise PolicyError(f"active project not found: {project_id}")

    def status(self) -> dict:
        with connect(self.settings, read_only=True) as connection:
            counts = {
                name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                for name in ("projects", "documents", "passages", "research_items", "verified_evidence", "passages_search_fts")
            }
            integrity = connection.execute("PRAGMA quick_check(5)").fetchall()
        return {
            "ok": True,
            "protocol": "research-kb/v1",
            "schema_version": SCHEMA_VERSION,
            "database": str(self.settings.database),
            "counts": counts,
            "integrity": [row[0] for row in integrity],
            "retrieval": {
                "lexical": True,
                "semantic": self.settings.semantic_enabled,
                "local_model_required": False,
            },
        }

    def search_corpus(
        self,
        *,
        project_id: str,
        query: str,
        search_mode: str = "auto",
        match_strategy: str = "auto",
        source_types: list[str] | None = None,
        languages: list[str] | None = None,
        document_ids: list[str] | None = None,
        reliability_levels: list[str] | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        top_k: int = 10,
        diversify_results: bool = True,
        include_possible_counterevidence: bool = False,
    ) -> dict:
        query = validate_query(self.settings, query)
        top_k = bounded_int(top_k, minimum=1, maximum=self.settings.limits.max_top_k, name="top_k")
        mode = self.settings.default_search_mode if search_mode == "auto" else search_mode
        if mode != "lexical":
            raise PolicyError("semantic retrieval is disabled in v1; use lexical or auto")
        requested_strategy = str(match_strategy or "auto").casefold()
        if requested_strategy not in {"all", "any", "auto"}:
            raise PolicyError("match_strategy must be all, any, or auto")
        effective_strategy = "all" if requested_strategy == "auto" else requested_strategy
        query_relaxed = False
        try:
            match_query = fts_match_query(query, match_strategy=effective_strategy)
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc
        source_types = list(source_types or [])
        languages = list(languages or [])
        document_ids = list(document_ids or [])
        reliability_levels = list(reliability_levels or [])
        for name, values, maximum in (
            ("source_types", source_types, 20),
            ("languages", languages, 20),
            ("document_ids", document_ids, 100),
            ("reliability_levels", reliability_levels, 20),
        ):
            if len(values) > maximum:
                raise PolicyError(f"{name} contains too many values")

        with transaction(self.settings) as connection:
            self._require_project(connection, project_id)
            self._touch_session(connection, project_id)
            enforce_session_quota(connection, self.settings, self.actor, "search")
            def execute_search(table: str, current_match_query: str) -> list[Any]:
                conditions = ["ps.project_id = ?", f"{table} MATCH ?"]
                parameters: list[Any] = [project_id, current_match_query]

                def add_in(column: str, values: list[str]) -> None:
                    if values:
                        conditions.append(f"{column} IN ({','.join('?' for _ in values)})")
                        parameters.extend(values)

                add_in("d.source_type", source_types)
                add_in("d.language", languages)
                add_in("d.document_id", document_ids)
                add_in("d.reliability_status", reliability_levels)
                if date_from:
                    conditions.append("d.source_date >= ?")
                    parameters.append(date_from)
                if date_to:
                    conditions.append("d.source_date <= ?")
                    parameters.append(date_to)
                fetch_limit = min(self.settings.limits.max_top_k * 4, top_k * 4)
                parameters.append(fetch_limit)
                return connection.execute(
                    f"""
                    SELECT p.passage_id, p.document_id, p.ordinal, p.location_json, p.text,
                           d.title, d.creator, d.source_type, d.language, d.source_date,
                           d.source_version, d.content_hash, d.metadata_json,
                           d.reliability_status, d.verification_status,
                           bm25({table}, 0.0, 3.0, 1.0) AS rank
                    FROM {table}
                    JOIN passages p ON p.passage_id = {table}.passage_id
                    JOIN documents d ON d.document_id = p.document_id
                    JOIN project_sources ps ON ps.document_id = d.document_id
                    WHERE {' AND '.join(conditions)}
                    ORDER BY rank
                    LIMIT ?
                    """,
                    parameters,
                ).fetchall()

            rows = execute_search("passages_search_fts", match_query)
            if not rows:
                rows = execute_search("passages_fts", match_query)
            if not rows and requested_strategy == "auto":
                effective_strategy = "any"
                query_relaxed = True
                try:
                    match_query = fts_match_query(query, match_strategy=effective_strategy)
                except ValueError as exc:
                    raise PolicyError(str(exc)) from exc
                rows = execute_search("passages_search_fts", match_query)
                if not rows:
                    rows = execute_search("passages_fts", match_query)
            selected = []
            selected_ids: set[str] = set()
            seen_documents: set[str] = set()
            if diversify_results:
                for row in rows:
                    if row["document_id"] not in seen_documents:
                        selected.append(row)
                        selected_ids.add(row["passage_id"])
                        seen_documents.add(row["document_id"])
                    if len(selected) == top_k:
                        break
            for row in rows:
                if len(selected) == top_k:
                    break
                if row["passage_id"] not in selected_ids:
                    selected.append(row)
                    selected_ids.add(row["passage_id"])
            results = [
                {
                    "passage_id": row["passage_id"],
                    "document_id": row["document_id"],
                    "title": row["title"],
                    "creator": row["creator"],
                    "source_type": row["source_type"],
                    "language": row["language"],
                    "date": row["source_date"],
                    "version": row["source_version"],
                    "location": json.loads(row["location_json"]),
                    "excerpt": excerpt_from_original(row["text"], query),
                    "retrieval_method": "sqlite_fts5_deterministic_terms",
                    "score": round(-float(row["rank"]), 6),
                    "reliability_status": row["reliability_status"],
                    "verification_status": row["verification_status"],
                    "citation_eligible": False,
                    "citation_locator": _citation_locator(
                        row, passage_id=row["passage_id"], location=json.loads(row["location_json"])
                    ),
                }
                for row in selected
            ]
            connection.execute(
                """
                INSERT INTO search_events(
                    session_id, project_id, query_text, query_hash,
                    parameters_json, result_ids_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    self.actor.session_id,
                    project_id,
                    query,
                    _hash(query),
                    _json({
                        "mode": mode,
                        "top_k": top_k,
                        "match_strategy_requested": requested_strategy,
                        "match_strategy": effective_strategy,
                        "query_relaxed": query_relaxed,
                        "include_possible_counterevidence": bool(include_possible_counterevidence),
                    }),
                    _json([item["passage_id"] for item in results]),
                ),
            )
            response = {
                "query": query,
                "search_mode": mode,
                "match_strategy": effective_strategy,
                "query_relaxed": query_relaxed,
                "count": len(results),
                "results": results,
            }
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=project_id,
                operation="search_corpus",
                parameters={
                    "query_hash": _hash(query),
                    "top_k": top_k,
                    "match_strategy_requested": requested_strategy,
                    "match_strategy": effective_strategy,
                    "query_relaxed": query_relaxed,
                },
                result={"count": len(results)},
            )
            return response

    def get_passage(self, *, project_id: str, passage_id: str, context: int = 1) -> dict:
        context = bounded_int(
            context, minimum=0, maximum=self.settings.limits.max_context_passages, name="context"
        )
        with connect(self.settings, read_only=True) as connection:
            self._require_project(connection, project_id)
            row = connection.execute(
                """
                SELECT p.*, d.title, d.creator, d.source_type, d.language,
                       d.source_date, d.source_version, d.content_hash,
                       d.metadata_json, d.reliability_status, d.verification_status
                FROM passages p
                JOIN documents d ON d.document_id = p.document_id
                JOIN project_sources ps ON ps.document_id = d.document_id
                WHERE ps.project_id = ? AND p.passage_id = ?
                """,
                (project_id, passage_id),
            ).fetchone()
            if not row:
                raise KeyError(f"passage not found in project: {passage_id}")
            neighbors = connection.execute(
                """
                SELECT passage_id, ordinal, location_json, text
                FROM passages
                WHERE document_id = ? AND ordinal BETWEEN ? AND ?
                ORDER BY ordinal
                """,
                (row["document_id"], max(1, row["ordinal"] - context), row["ordinal"] + context),
            ).fetchall()
        metadata = json.loads(row["metadata_json"])
        passage_location = json.loads(row["location_json"])
        return {
            "passage_id": passage_id,
            "document_id": row["document_id"],
            "title": row["title"],
            "creator": row["creator"],
            "source_type": row["source_type"],
            "language": row["language"],
            "date": row["source_date"],
            "version": row["source_version"],
            "content_hash": row["content_hash"],
            "reliability_status": row["reliability_status"],
            "verification_status": row["verification_status"],
            "location": passage_location,
            "citation_record": _bibliographic_profile(row, metadata),
            "citation_locator": _citation_locator(
                row, passage_id=passage_id, location=passage_location
            ),
            "context": [
                {
                    "passage_id": item["passage_id"],
                    "ordinal": item["ordinal"],
                    "location": json.loads(item["location_json"]),
                    "text": item["text"],
                    "selected": item["passage_id"] == passage_id,
                }
                for item in neighbors
            ],
        }

    def get_document_metadata(self, *, project_id: str, document_id: str) -> dict:
        with connect(self.settings, read_only=True) as connection:
            self._require_project(connection, project_id)
            row = connection.execute(
                """
                SELECT d.*, COUNT(p.passage_id) AS passage_count
                FROM documents d
                JOIN project_sources ps ON ps.document_id = d.document_id
                LEFT JOIN passages p ON p.document_id = d.document_id
                WHERE ps.project_id = ? AND d.document_id = ?
                GROUP BY d.document_id
                """,
                (project_id, document_id),
            ).fetchone()
            if not row:
                raise KeyError(f"document not found in project: {document_id}")
        metadata = json.loads(row["metadata_json"])
        result = {
            key: row[key]
            for key in (
                "document_id", "content_hash", "title", "creator", "source_type",
                "language", "source_date", "source_version", "source_name",
                "reliability_status", "verification_status", "ingestion_method",
                "passage_count", "created_at",
            )
        }
        result["metadata"] = metadata
        result["citation_record"] = _bibliographic_profile(row, metadata)
        result["citation_locator"] = _citation_locator(row)
        return result

    def _create_item(
        self,
        connection,
        *,
        project_id: str,
        kind: str,
        status: str,
        payload: dict,
        passage_links: list[tuple[str, str]] | None = None,
        verified_links: list[tuple[str, str]] | None = None,
        supersedes_item_id: str | None = None,
        standard_checkpoint: bool = False,
    ) -> dict:
        if not self.actor.is_admin and status not in {"draft", "candidate"}:
            raise PolicyError("agents can create only draft or candidate items")
        enforce_session_quota(connection, self.settings, self.actor, "write")
        self._require_project(connection, project_id)

        payload_is_checkpoint = is_standard_checkpoint_payload(payload)
        if standard_checkpoint:
            if (
                kind != "note"
                or not payload_is_checkpoint
                or payload.get("checkpoint_version") != CHECKPOINT_VERSION
            ):
                raise PolicyError("checkpoint conflict: invalid server checkpoint payload")
            # This is deliberately inside the same BEGIN IMMEDIATE transaction
            # as the insert. It rechecks current, target classification, and
            # successor conflicts after all caller-side normalization.
            self._validate_checkpoint_successor(
                connection,
                project_id=project_id,
                supersedes_item_id=supersedes_item_id,
            )
        else:
            if kind == "note" and supersedes_item_id is not None:
                raise PolicyError(
                    "supersedes_item_id is only valid for a server-generated checkpoint"
                )
            if payload_is_checkpoint:
                raise PolicyError(
                    "checkpoint conflict: checkpoint payload requires server checkpoint context"
                )
            if supersedes_item_id:
                prior = connection.execute(
                    """
                    SELECT ri.item_id, ri.kind, riv.payload_json
                    FROM research_items ri
                    JOIN research_item_versions riv ON riv.item_id = ri.item_id
                    WHERE ri.item_id = ? AND ri.project_id = ?
                      AND riv.version_no = (
                          SELECT MAX(latest.version_no)
                          FROM research_item_versions latest
                          WHERE latest.item_id = ri.item_id
                      )
                    """,
                    (supersedes_item_id, project_id),
                ).fetchone()
                if not prior:
                    raise PolicyError("superseded item is not in the same project")
                try:
                    prior_payload = json.loads(prior["payload_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    prior_payload = None
                if (
                    prior["kind"] == "note"
                    and is_standard_checkpoint_payload(prior_payload)
                ):
                    raise PolicyError(
                        "checkpoint conflict: only a standard checkpoint may supersede a standard checkpoint"
                    )

        # No session state is touched until all target and checkpoint checks
        # have passed. The item, version, evidence links, and audit record are
        # then created by this same transaction.
        self._touch_session(connection, project_id)
        item_id = _id("item")
        if supersedes_item_id is not None and supersedes_item_id == item_id:
            raise PolicyError("successor cycle is not allowed")
        version_id = _id("ver")
        serialized = _json(payload)
        connection.execute(
            """
            INSERT INTO research_items(
                item_id, project_id, kind, status, created_by,
                supersedes_item_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            """,
            (item_id, project_id, kind, status, self.actor.actor_id, supersedes_item_id),
        )
        connection.execute(
            """
            INSERT INTO research_item_versions(
                version_id, item_id, version_no, payload_json, content_hash,
                created_by, created_at
            ) VALUES (?, ?, 1, ?, ?, ?, datetime('now'))
            """,
            (version_id, item_id, serialized, _hash(serialized), self.actor.actor_id),
        )
        for relation, passage_id in passage_links or []:
            allowed = connection.execute(
                """
                SELECT 1 FROM passages p JOIN project_sources ps ON ps.document_id = p.document_id
                WHERE ps.project_id = ? AND p.passage_id = ?
                """,
                (project_id, passage_id),
            ).fetchone()
            if not allowed:
                raise PolicyError(f"passage is outside project scope: {passage_id}")
            connection.execute(
                "INSERT INTO evidence_links VALUES (?, ?, ?, ?, NULL, datetime('now'))",
                (_id("lnk"), version_id, relation, passage_id),
            )
        for relation, evidence_id in verified_links or []:
            allowed = connection.execute(
                """
                SELECT 1 FROM verified_evidence ve
                JOIN project_sources ps ON ps.document_id = ve.document_id
                WHERE ps.project_id = ? AND ve.verified_evidence_id = ?
                """,
                (project_id, evidence_id),
            ).fetchone()
            if not allowed:
                raise PolicyError(f"verified evidence is outside project scope: {evidence_id}")
            connection.execute(
                "INSERT INTO evidence_links VALUES (?, ?, ?, NULL, ?, datetime('now'))",
                (_id("lnk"), version_id, relation, evidence_id),
            )
        result = {"item_id": item_id, "version_id": version_id, "kind": kind, "status": status}
        audit(
            connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
            session_id=self.actor.session_id, project_id=project_id,
            operation=f"submit_{kind}", parameters={"status": status}, result=result,
        )
        return result

    def _current_standard_checkpoints(self, connection, *, project_id: str) -> list[Any]:
        """Return current checkpoint notes using only their latest payload version.

        The query is intentionally performed inside the caller's write
        transaction. ``BEGIN IMMEDIATE`` serializes competing checkpoint
        writers, so the result cannot become stale before the successor is
        inserted.
        """

        rows = connection.execute(
            """
            SELECT ri.item_id, ri.project_id, ri.kind, ri.status,
                   ri.supersedes_item_id, riv.payload_json
            FROM research_items ri
            JOIN research_item_versions riv ON riv.item_id = ri.item_id
            WHERE ri.project_id = ?
              AND ri.kind = 'note'
              AND ri.status NOT IN ('archived', 'rejected')
              AND riv.version_no = (
                  SELECT MAX(latest.version_no)
                  FROM research_item_versions latest
                  WHERE latest.item_id = ri.item_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM research_items successor
                  WHERE successor.supersedes_item_id = ri.item_id
              )
            ORDER BY ri.item_id
            """,
            (project_id,),
        ).fetchall()
        current: list[Any] = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = None
            # SG-1A already uses the schema marker as the compatibility
            # discriminator. Newly created checkpoints additionally carry
            # checkpoint_version, while older schema-marked records remain
            # recognizable and are never rewritten here.
            if is_standard_checkpoint_payload(payload):
                current.append(row)
        return current

    def _cross_kind_checkpoint_successors(
        self,
        connection,
        *,
        project_id: str,
    ) -> list[Any]:
        """Return historical non-checkpoint successors of standard checkpoints."""

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
            WHERE target.project_id = ?
              AND target.kind = 'note'
            ORDER BY target.item_id, successor.item_id
            """,
            (project_id,),
        ).fetchall()
        anomalies: list[Any] = []
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
        return anomalies

    def _validate_checkpoint_successor(
        self,
        connection,
        *,
        project_id: str,
        supersedes_item_id: str | None,
    ) -> None:
        """Validate the one-current checkpoint transition in a write txn."""

        if self._cross_kind_checkpoint_successors(connection, project_id=project_id):
            raise PolicyError(
                "checkpoint conflict: cross-kind checkpoint successor requires governance"
            )
        current = self._current_standard_checkpoints(connection, project_id=project_id)
        if len(current) > 1:
            raise PolicyError("checkpoint conflict: multiple current checkpoints")
        if not current:
            if supersedes_item_id is not None:
                raise PolicyError("checkpoint conflict: no current checkpoint to supersede")
            return

        current_id = str(current[0]["item_id"])
        if supersedes_item_id != current_id:
            raise PolicyError(
                "checkpoint conflict: supersedes_item_id must target the current checkpoint"
            )

        target = connection.execute(
            """
            SELECT ri.item_id, ri.project_id, ri.kind, ri.status, riv.payload_json
            FROM research_items ri
            JOIN research_item_versions riv ON riv.item_id = ri.item_id
            WHERE ri.item_id = ? AND ri.project_id = ?
              AND riv.version_no = (
                  SELECT MAX(latest.version_no)
                  FROM research_item_versions latest
                  WHERE latest.item_id = ri.item_id
              )
            """,
            (supersedes_item_id, project_id),
        ).fetchone()
        if not target:
            raise PolicyError("checkpoint conflict: supersedes target is outside project")
        if target["kind"] != "note":
            raise PolicyError("checkpoint conflict: supersedes target is not a note")
        if target["status"] in {"archived", "rejected"}:
            raise PolicyError("checkpoint conflict: supersedes target is not active")
        try:
            payload = json.loads(target["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = None
        if not isinstance(payload, dict) or payload.get("schema") != CHECKPOINT_SCHEMA:
            raise PolicyError("checkpoint conflict: supersedes target is not a standard checkpoint")
        successor = connection.execute(
            """
            SELECT 1 FROM research_items
            WHERE supersedes_item_id = ?
            LIMIT 1
            """,
            (supersedes_item_id,),
        ).fetchone()
        if successor:
            raise PolicyError("checkpoint conflict: supersedes target already has a successor")

    def save_research_note(
        self,
        *,
        project_id: str,
        title: str,
        body: str,
        note_purpose: str = "research_note",
        supersedes_item_id: str | None = None,
    ) -> dict:
        project_id = validate_text(project_id, "project_id", 256)
        title = validate_text(title, "title", 500)
        body = validate_text(body, "body", 8000)
        note_purpose = validate_text(note_purpose, "note_purpose", 32)
        if note_purpose not in NOTE_PURPOSES:
            raise PolicyError("note_purpose must be research_note or checkpoint")
        if supersedes_item_id is not None:
            supersedes_item_id = validate_text(supersedes_item_id, "supersedes_item_id", 256)
        if note_purpose == "research_note" and supersedes_item_id is not None:
            raise PolicyError(
                "supersedes_item_id is only valid when note_purpose is checkpoint"
            )

        if note_purpose == "checkpoint":
            payload = {
                "schema": CHECKPOINT_SCHEMA,
                "checkpoint_version": CHECKPOINT_VERSION,
                "title": title,
                "body": body,
                "checkpoint_metadata": {
                    "project_id": project_id,
                    "created_by": self.actor.actor_id,
                    "session_id": self.actor.session_id,
                    "created_at": _iso(_now()),
                },
            }
        else:
            payload = {
                "title": title,
                "body": body,
                "epistemic_status": "unresolved",
            }

        with transaction(self.settings) as connection:
            return self._create_item(
                connection, project_id=project_id, kind="note", status="draft",
                payload=payload, supersedes_item_id=supersedes_item_id,
                standard_checkpoint=note_purpose == "checkpoint",
            )

    def submit_hypothesis(
        self,
        *,
        project_id: str,
        title: str,
        claim: str,
        epistemic_status: str,
        supporting_passage_ids: list[str] | None = None,
        counter_passage_ids: list[str] | None = None,
        alternative_explanations: list[str] | None = None,
        open_questions: list[str] | None = None,
        confidence: str = "low",
        status: str = "candidate",
        supersedes_item_id: str | None = None,
    ) -> dict:
        if epistemic_status not in EPISTEMIC_STATUSES - {"source_fact", "counterevidence"}:
            raise PolicyError("invalid epistemic status for a hypothesis")
        if confidence not in {"low", "medium", "high"}:
            raise PolicyError("confidence must be low, medium, or high")
        links = [("supports", value) for value in supporting_passage_ids or []]
        links += [("counters", value) for value in counter_passage_ids or []]
        payload = {
            "title": title.strip(),
            "claim": claim.strip(),
            "epistemic_status": epistemic_status,
            "alternative_explanations": alternative_explanations or [],
            "open_questions": open_questions or [],
            "confidence": confidence,
        }
        with transaction(self.settings) as connection:
            return self._create_item(
                connection, project_id=project_id, kind="hypothesis", status=status,
                payload=payload, passage_links=links, supersedes_item_id=supersedes_item_id,
            )

    def submit_objection(
        self,
        *,
        project_id: str,
        target_item_id: str,
        objection_type: str,
        text: str,
        passage_ids: list[str] | None = None,
        status: str = "candidate",
    ) -> dict:
        payload = {
            "target_item_id": target_item_id,
            "objection_type": objection_type,
            "text": text.strip(),
            "epistemic_status": "counterevidence",
        }
        with transaction(self.settings) as connection:
            target = connection.execute(
                "SELECT 1 FROM research_items WHERE item_id = ? AND project_id = ?",
                (target_item_id, project_id),
            ).fetchone()
            if not target:
                raise PolicyError("objection target is outside project scope")
            return self._create_item(
                connection, project_id=project_id, kind="objection", status=status,
                payload=payload,
                passage_links=[("counters", value) for value in passage_ids or []],
            )

    def verify_quote(self, *, project_id: str, passage_id: str, quote: str) -> dict:
        quote = str(quote or "").strip()
        if len(quote) < 8:
            raise PolicyError("quote must contain at least 8 characters")
        with transaction(self.settings) as connection:
            self._require_project(connection, project_id)
            row = connection.execute(
                """
                SELECT p.text, p.location_json, d.document_id, d.content_hash,
                       COALESCE(d.source_version, 'unknown') AS source_version
                FROM passages p
                JOIN documents d ON d.document_id = p.document_id
                JOIN project_sources ps ON ps.document_id = d.document_id
                WHERE ps.project_id = ? AND p.passage_id = ?
                """,
                (project_id, passage_id),
            ).fetchone()
            if not row:
                raise KeyError(f"passage not found in project: {passage_id}")
            if quote not in row["text"]:
                result = {"verified": False, "reason": "quote_is_not_an_exact_substring"}
                audit(
                    connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                    session_id=self.actor.session_id, project_id=project_id,
                    operation="verify_quote", parameters={"passage_id": passage_id, "quote_hash": _hash(quote)},
                    result=result, success=False,
                )
                return result
            raw_token = secrets.token_urlsafe(32)
            token_id = _id("tok")
            expires = _now() + timedelta(seconds=self.settings.limits.verification_token_ttl_seconds)
            connection.execute(
                """
                INSERT INTO verification_tokens(
                    token_id, token_hash, passage_id, document_hash, quote_text,
                    quote_hash, issued_to, issued_session_id, expires_at, consumed_at, created_at,
                    project_id, source_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    token_id, _hash(raw_token), passage_id, row["content_hash"], quote,
                    _hash(quote), self.actor.actor_id, self.actor.session_id, _iso(expires), _iso(_now()),
                    project_id, row["source_version"],
                ),
            )
            result = {
                "verified": True,
                "verification_token": raw_token,
                "expires_at": _iso(expires),
                "passage_id": passage_id,
                "project_id": project_id,
                "document_hash": row["content_hash"],
                "source_version": row["source_version"],
                "location": json.loads(row["location_json"]),
            }
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=project_id,
                operation="verify_quote", parameters={"passage_id": passage_id, "quote_hash": _hash(quote)},
                result={key: value for key, value in result.items() if key != "verification_token"},
            )
            return result

    def submit_verified_evidence(self, *, project_id: str, verification_token: str) -> dict:
        token_hash = _hash(verification_token)
        with transaction(self.settings) as connection:
            self._require_project(connection, project_id)
            row = connection.execute(
                """
                SELECT vt.*, p.document_id, p.location_json, p.text,
                       d.content_hash AS current_hash,
                       COALESCE(d.source_version, 'unknown') AS current_source_version
                FROM verification_tokens vt
                JOIN passages p ON p.passage_id = vt.passage_id
                JOIN documents d ON d.document_id = p.document_id
                JOIN project_sources ps ON ps.document_id = d.document_id
                WHERE vt.token_hash = ?
                  AND vt.project_id = ?
                  AND ps.project_id = ?
                """,
                (token_hash, project_id, project_id),
            ).fetchone()
            if not row:
                raise PolicyError("invalid verification token")
            if row["issued_to"] != self.actor.actor_id:
                raise PolicyError("verification token was issued to another actor")
            if row["issued_session_id"] != self.actor.session_id:
                raise PolicyError("verification token was issued to another session")
            if row["consumed_at"]:
                raise PolicyError("verification token has already been consumed")
            if datetime.fromisoformat(row["expires_at"]) < _now():
                raise PolicyError("verification token has expired")
            if (
                row["current_hash"] != row["document_hash"]
                or row["current_source_version"] != row["source_version"]
                or row["quote_text"] not in row["text"]
            ):
                raise PolicyError("source content or version changed after verification")
            evidence_id = _id("ve")
            connection.execute(
                """
                INSERT INTO verified_evidence(
                    verified_evidence_id, passage_id, document_id, document_hash,
                    quote_text, quote_hash, location_json, verified_by, verified_at,
                    source_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id, row["passage_id"], row["document_id"], row["document_hash"],
                    row["quote_text"], row["quote_hash"], row["location_json"],
                    self.actor.actor_id, _iso(_now()), row["source_version"],
                ),
            )
            connection.execute(
                """
                INSERT INTO evidence_status_history(
                    verified_evidence_id, status, reason, actor_id, actor_kind, created_at
                ) VALUES (?, 'candidate', 'source consistency verified', ?, ?, ?)
                """,
                (evidence_id, self.actor.actor_id, self.actor.actor_kind, _iso(_now())),
            )
            consumed = connection.execute(
                """
                UPDATE verification_tokens
                SET consumed_at = ?
                WHERE token_id = ? AND consumed_at IS NULL
                """,
                (_iso(_now()), row["token_id"]),
            )
            if consumed.rowcount != 1:
                raise PolicyError("verification token has already been consumed")
            result = {
                "verified_evidence_id": evidence_id,
                "passage_id": row["passage_id"],
                "project_id": project_id,
                "status": "candidate",
            }
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=project_id,
                operation="submit_verified_evidence", parameters={"token_id": row["token_id"]}, result=result,
            )
            return result

    def submit_research_report(
        self,
        *,
        project_id: str,
        question: str,
        summary: str,
        claims: list[dict],
        strongest_objection: str,
        alternative_explanations: list[str],
        unresolved_questions: list[str],
        evidence_limits: list[str],
        next_steps: list[str],
        research_leads: list[dict] | None = None,
        source_table: list[dict] | None = None,
        evidence_citation_map: list[dict] | None = None,
        status: str = "candidate",
        supersedes_item_id: str | None = None,
        deliverable_layer: str | None = None,
        artifact_profile: str | None = None,
        writing_policy_id: str | None = None,
        writing_policy_version: str | None = None,
        writing_policy_snapshot: dict | None = None,
        writing_policy_overrides: dict | None = None,
        compression_review_status: str | None = None,
        writing_audit_summary: dict[str, int] | None = None,
    ) -> dict:
        if not claims:
            raise PolicyError("report must contain at least one structured claim")
        verified_ids: list[str] = []
        clean_claims = []
        for index, claim in enumerate(claims, start=1):
            epistemic = str(claim.get("epistemic_status") or "")
            if epistemic not in EPISTEMIC_STATUSES:
                raise PolicyError(f"claim {index} has invalid epistemic_status")
            evidence_ids = [str(value) for value in claim.get("verified_evidence_ids", [])]
            if epistemic == "source_fact" and not evidence_ids:
                raise PolicyError(f"source_fact claim {index} requires verified evidence")
            verified_ids.extend(evidence_ids)
            clean_claims.append(
                {
                    "claim_id": str(claim.get("claim_id") or f"C{index:03d}"),
                    "text": str(claim.get("text") or "").strip(),
                    "epistemic_status": epistemic,
                    "verified_evidence_ids": evidence_ids,
                }
            )
        clean_leads = list(research_leads or [])
        if clean_leads and not 3 <= len(clean_leads) <= 6:
            raise PolicyError("research_leads must contain between 3 and 6 leads")
        lead_passage_ids: list[str] = []
        normalized_leads: list[dict[str, Any]] = []
        for index, lead in enumerate(clean_leads, start=1):
            if not isinstance(lead, dict):
                raise PolicyError(f"research lead {index} is invalid")
            required = (
                "idea", "source_bridges", "supporting_passage_ids",
                "why_not_literature_summary", "possible_counterevidence",
                "missing_evidence", "next_search", "epistemic_status", "confidence",
            )
            if any(field not in lead for field in required):
                raise PolicyError(f"research lead {index} is incomplete")
            epistemic = str(lead["epistemic_status"])
            if epistemic not in {"analytical_inference", "exploratory_hypothesis", "open_question", "unresolved"}:
                raise PolicyError(f"research lead {index} has invalid epistemic_status")
            if str(lead["confidence"]) not in {"low", "medium", "high"}:
                raise PolicyError(f"research lead {index} has invalid confidence")
            supporting = lead["supporting_passage_ids"]
            if not isinstance(supporting, list) or len(supporting) > 50:
                raise PolicyError(f"research lead {index} has too many supporting passages")
            support_ids = [str(value).strip() for value in supporting if str(value).strip()]
            lead_passage_ids.extend(support_ids)
            normalized_leads.append(
                {
                    "idea": str(lead["idea"]).strip(),
                    "source_bridges": [str(value).strip() for value in lead["source_bridges"]],
                    "supporting_passage_ids": support_ids,
                    "why_not_literature_summary": str(lead["why_not_literature_summary"]).strip(),
                    "possible_counterevidence": [str(value).strip() for value in lead["possible_counterevidence"]],
                    "missing_evidence": [str(value).strip() for value in lead["missing_evidence"]],
                    "next_search": [str(value).strip() for value in lead["next_search"]],
                    "epistemic_status": epistemic,
                    "confidence": str(lead["confidence"]),
                }
            )
        clean_source_table = list(source_table or [])
        clean_evidence_map = list(evidence_citation_map or [])
        if len(clean_source_table) > 50 or len(clean_evidence_map) > 100:
            raise PolicyError("citation tables are too large")
        if (
            compression_review_status is not None
            and compression_review_status not in COMPRESSION_REVIEW_STATUSES
        ):
            raise PolicyError(
                "compression_review_status must be one of "
                + ", ".join(COMPRESSION_REVIEW_STATUSES)
            )
        clean_audit_summary = (
            validate_writing_audit_summary(writing_audit_summary)
            if writing_audit_summary is not None
            else None
        )
        with transaction(self.settings) as connection:
            policy_args = (
                deliverable_layer,
                artifact_profile,
                writing_policy_id,
                writing_policy_version,
                writing_policy_snapshot,
                writing_policy_overrides,
            )
            resolved_policy: dict | None = None
            if any(value is not None for value in policy_args):
                project_row = connection.execute(
                    "SELECT config_json FROM projects WHERE project_id = ?",
                    (project_id,),
                ).fetchone()
                project_config = (
                    json.loads(project_row["config_json"] or "{}")
                    if project_row
                    else {}
                )
                resolved_policy = resolve_submission_policy(
                    deliverable_layer=deliverable_layer,
                    artifact_profile=artifact_profile,
                    writing_policy_id=writing_policy_id,
                    writing_policy_version=writing_policy_version,
                    writing_policy_snapshot=writing_policy_snapshot,
                    writing_policy_overrides=writing_policy_overrides,
                    project_config=project_config,
                )
            # Client citation fields are display hints only. The stored report
            # always receives records rebuilt from the active project's rows.
            canonical_source_table: list[dict[str, Any]] = []
            for entry in clean_source_table:
                if not isinstance(entry, dict) or not entry.get("document_id"):
                    raise PolicyError("source citation table entry is invalid")
                document_id = str(entry["document_id"]).strip()
                row = connection.execute(
                    """
                    SELECT d.*
                    FROM documents d
                    JOIN project_sources ps ON ps.document_id = d.document_id
                    WHERE ps.project_id = ? AND d.document_id = ?
                    """,
                    (project_id, document_id),
                ).fetchone()
                if not row:
                    raise PolicyError("source citation is outside project scope")
                metadata = json.loads(row["metadata_json"])
                canonical_source_table.append(
                    {
                        "document_id": row["document_id"],
                        "citation_record": _bibliographic_profile(row, metadata),
                    }
                )

            canonical_evidence_map: list[dict[str, Any]] = []
            for entry in clean_evidence_map:
                if not isinstance(entry, dict):
                    raise PolicyError("evidence citation map entry is invalid")
                evidence_id = str(entry.get("evidence_id") or "").strip()
                passage_id = str(entry.get("passage_id") or "").strip()
                document_id = str(entry.get("document_id") or "").strip()
                if not evidence_id or not passage_id or not document_id:
                    raise PolicyError("evidence citation map entry is invalid")
                row = connection.execute(
                    """
                    SELECT ve.verified_evidence_id AS evidence_id,
                           ve.passage_id AS passage_id,
                           ve.document_id AS document_id,
                           p.location_json,
                           d.content_hash, d.source_type, d.source_version,
                           d.metadata_json
                    FROM verified_evidence ve
                    JOIN passages p ON p.passage_id = ve.passage_id
                    JOIN documents d ON d.document_id = ve.document_id
                    JOIN project_sources ps ON ps.document_id = ve.document_id
                    WHERE ps.project_id = ?
                      AND ve.verified_evidence_id = ?
                      AND ve.passage_id = ?
                      AND ve.document_id = ?
                    """,
                    (project_id, evidence_id, passage_id, document_id),
                ).fetchone()
                if not row:
                    raise PolicyError("evidence citation is outside project scope")
                metadata = json.loads(row["metadata_json"])
                location = json.loads(row["location_json"])
                canonical_evidence_map.append(
                    {
                        "evidence_id": row["evidence_id"],
                        "passage_id": row["passage_id"],
                        "document_id": row["document_id"],
                        "citation_record": _bibliographic_profile(row, metadata),
                        "citation_locator": _citation_locator(
                            row, passage_id=row["passage_id"], location=location
                        ),
                    }
                )

            payload = {
                "question": question.strip(),
                "summary": summary.strip(),
                "claims": clean_claims,
                "strongest_objection": strongest_objection.strip(),
                "alternative_explanations": alternative_explanations,
                "unresolved_questions": unresolved_questions,
                "evidence_limits": evidence_limits,
                "next_steps": next_steps,
                "research_leads": normalized_leads,
                "source_table": canonical_source_table,
                "evidence_citation_map": canonical_evidence_map,
            }
            created = self._create_item(
                connection, project_id=project_id, kind="report", status=status,
                payload=payload,
                passage_links=[("supports", value) for value in dict.fromkeys(lead_passage_ids)],
                verified_links=[("supports", value) for value in dict.fromkeys(verified_ids)],
                supersedes_item_id=supersedes_item_id,
            )
            report_manifest_id = _id("rmf")
            connection.execute(
                """
                INSERT INTO report_manifest(
                    report_manifest_id, report_version_id, protocol_project_id,
                    claim_revision_ids_json, evidence_revision_ids_json,
                    passage_revision_ids_json, verification_event_ids_json,
                    approval_event_ids_json, source_snapshot_ids_json,
                    constraint_revision_id, research_project_id,
                    project_export_ids_json, cross_project_link_ids_json,
                    deliverable_layer, artifact_profile,
                    writing_policy_id, writing_policy_version,
                    writing_policy_snapshot_json, compression_review_status,
                    writing_audit_summary_json, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    report_manifest_id, created["version_id"], project_id,
                    _json(list(dict.fromkeys(claim["claim_id"] for claim in clean_claims))),
                    _json(list(dict.fromkeys(verified_ids))),
                    _json(list(dict.fromkeys(lead_passage_ids))),
                    "[]", "[]", "[]", None, None, "[]", "[]",
                    resolved_policy["deliverable_layer"] if resolved_policy else None,
                    resolved_policy["profile"] if resolved_policy else None,
                    resolved_policy["policy_id"] if resolved_policy else None,
                    resolved_policy["policy_version"] if resolved_policy else None,
                    _json(resolved_policy["snapshot"]) if resolved_policy else None,
                    compression_review_status,
                    _json(clean_audit_summary) if clean_audit_summary is not None else None,
                    self.actor.actor_id,
                ),
            )
            created["report_manifest_id"] = report_manifest_id
            created["report_revision_id"] = created["version_id"]
            created["deliverable_layer"] = (
                resolved_policy["deliverable_layer"] if resolved_policy else None
            )
            created["artifact_profile"] = (
                resolved_policy["profile"] if resolved_policy else None
            )
            created["writing_policy_id"] = (
                resolved_policy["policy_id"] if resolved_policy else None
            )
            created["writing_policy_version"] = (
                resolved_policy["policy_version"] if resolved_policy else None
            )
            created["writing_policy_snapshot"] = (
                resolved_policy["snapshot"] if resolved_policy else None
            )
            created["compression_review_status"] = compression_review_status
            created["writing_audit_summary"] = clean_audit_summary
            return created

    def request_user_approval(
        self,
        *,
        project_id: str,
        item_id: str | None = None,
        verified_evidence_id: str | None = None,
        target_type: str = "research_item",
        rationale: str = "",
    ) -> dict:
        with transaction(self.settings) as connection:
            self._require_project(connection, project_id)
            enforce_session_quota(connection, self.settings, self.actor, "write")
            if target_type == "research_item":
                if not item_id or verified_evidence_id:
                    raise PolicyError("research_item approval requires exactly one item_id")
                row = connection.execute(
                    "SELECT status FROM research_items WHERE item_id = ? AND project_id = ?",
                    (item_id, project_id),
                ).fetchone()
                if not row:
                    raise PolicyError("item is outside project scope")
                target_id = item_id
                existing = connection.execute(
                    """
                    SELECT request_id FROM approval_requests_v2
                    WHERE project_id = ? AND target_type = 'research_item'
                      AND item_id = ? AND status = 'pending'
                    ORDER BY created_at LIMIT 1
                    """,
                    (project_id, item_id),
                ).fetchone()
            elif target_type == "evidence":
                if not verified_evidence_id or item_id:
                    raise PolicyError("evidence approval requires exactly one verified_evidence_id")
                row = connection.execute(
                    """
                    SELECT ve.verified_evidence_id,
                           COALESCE((
                               SELECT esh.status
                               FROM evidence_status_history esh
                               WHERE esh.verified_evidence_id = ve.verified_evidence_id
                               ORDER BY esh.status_event_id DESC LIMIT 1
                           ), 'candidate') AS status
                    FROM verified_evidence ve
                    JOIN project_sources ps ON ps.document_id = ve.document_id
                    WHERE ve.verified_evidence_id = ? AND ps.project_id = ?
                    """,
                    (verified_evidence_id, project_id),
                ).fetchone()
                if not row:
                    raise PolicyError("evidence is outside project scope")
                target_id = verified_evidence_id
                existing = connection.execute(
                    """
                    SELECT request_id FROM approval_requests_v2
                    WHERE project_id = ? AND target_type = 'evidence'
                      AND verified_evidence_id = ? AND status = 'pending'
                    ORDER BY created_at LIMIT 1
                    """,
                    (project_id, verified_evidence_id),
                ).fetchone()
            else:
                raise PolicyError("target_type must be research_item or evidence")

            if existing:
                return {
                    "request_id": existing["request_id"],
                    "target_type": target_type,
                    "target_id": target_id,
                    "status": "pending",
                    "duplicate": True,
                }
            if row["status"] != "candidate":
                raise PolicyError("only candidate items or evidence can enter review")

            request_id = _id("apr")
            connection.execute(
                """
                INSERT INTO approval_requests_v2(
                    request_id, project_id, target_type, item_id, verified_evidence_id,
                    requested_by, requested_status, status, rationale, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'accepted', 'pending', ?, datetime('now'))
                """,
                (
                    request_id, project_id, target_type,
                    item_id if target_type == "research_item" else None,
                    verified_evidence_id if target_type == "evidence" else None,
                    self.actor.actor_id, rationale,
                ),
            )
            if target_type == "research_item":
                connection.execute(
                    "UPDATE research_items SET status = 'under_review', updated_at = datetime('now') WHERE item_id = ?",
                    (item_id,),
                )
            result = {
                "request_id": request_id,
                "target_type": target_type,
                "target_id": target_id,
                "status": "pending",
            }
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=project_id,
                operation="request_user_approval", parameters={"target_type": target_type, "target_id": target_id}, result=result,
            )
            return result

    def decide_approval(self, *, request_id: str, approve: bool, note: str = "") -> dict:
        require_admin(self.actor)
        with transaction(self.settings) as connection:
            row = connection.execute(
                """
                SELECT * FROM approval_requests_v2
                WHERE request_id = ? AND status = 'pending'
                """,
                (request_id,),
            ).fetchone()
            if not row:
                raise PolicyError("pending approval request not found")
            if approve and row["target_type"] == "research_item":
                successor = connection.execute(
                    """
                    SELECT 1 FROM research_items
                    WHERE project_id = ? AND supersedes_item_id = ?
                    LIMIT 1
                    """,
                    (row["project_id"], row["item_id"]),
                ).fetchone()
                if successor:
                    raise PolicyError("cannot approve an item that has an existing successor")
            decision = "approved" if approve else "rejected"
            connection.execute(
                """
                UPDATE approval_requests_v2
                SET status = ?, decided_by = ?, decision_note = ?, decided_at = datetime('now')
                WHERE request_id = ? AND status = 'pending'
                """,
                (decision, self.actor.actor_id, note, request_id),
            )
            if row["target_type"] == "research_item":
                item_status = "accepted" if approve else "rejected"
                connection.execute(
                    "UPDATE research_items SET status = ?, updated_at = datetime('now') WHERE item_id = ?",
                    (item_status, row["item_id"]),
                )
                target_id = row["item_id"]
            else:
                evidence_status = "accepted" if approve else "rejected"
                connection.execute(
                    """
                    INSERT INTO evidence_status_history(
                        verified_evidence_id, status, reason, actor_id, actor_kind, created_at
                    ) VALUES (?, ?, ?, ?, ?, datetime('now'))
                    """,
                    (
                        row["verified_evidence_id"], evidence_status, note,
                        self.actor.actor_id, self.actor.actor_kind,
                    ),
                )
                target_id = row["verified_evidence_id"]
            result = {
                "request_id": request_id,
                "target_type": row["target_type"],
                "target_id": target_id,
                "decision": decision,
            }
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=row["project_id"],
                operation="decide_approval", parameters={"request_id": request_id}, result=result,
            )
            return result

    def get_research_context(
        self,
        *,
        project_id: str,
        detail: str = "brief",
        item_id: str | None = None,
        section: str | None = None,
        offset: int = 0,
        limit: int | None = None,
        cursor: str | None = None,
        chunk_size: int = 1400,
    ) -> dict:
        """Return a bounded, project-scoped research index or item section.

        The legacy ``project_id``/``detail`` call remains valid.  Large payloads
        are deliberately not aggregated: callers first list the lightweight
        index, then address one stable item and one payload section at a time.
        """
        if detail not in {"brief", "full"}:
            raise PolicyError("detail must be brief or full")
        if item_id is not None and (
            not isinstance(item_id, str) or not item_id.strip() or len(item_id) > 256
        ):
            raise PolicyError("item_id is invalid")
        if section is not None and (
            not isinstance(section, str) or not section.strip() or len(section) > 128
        ):
            raise PolicyError("section is invalid")
        if cursor is not None and (
            not isinstance(cursor, str) or not cursor.strip() or len(cursor) > 512
        ):
            raise PolicyError("cursor is invalid")
        if section is not None and item_id is None:
            raise PolicyError("section requires item_id")
        if cursor is not None and (item_id is not None or section is not None):
            raise PolicyError("cursor is only valid for the research item index")
        offset = bounded_int(offset, minimum=0, maximum=1_000_000, name="offset")
        if limit is None:
            limit = 10 if detail == "brief" else 5
        limit = bounded_int(limit, minimum=1, maximum=20, name="limit")
        chunk_size = bounded_int(chunk_size, minimum=256, maximum=2400, name="chunk_size")
        maximum = max(256, int(self.settings.limits.max_return_chars))
        # Leave room for the protocol envelope, item metadata and JSON syntax.
        safe_payload_budget = max(512, maximum - 900)
        item_payload_budget = max(256, safe_payload_budget - 700)
        chunk_size = min(chunk_size, safe_payload_budget)

        with connect(self.settings, read_only=True) as connection:
            self._require_project(connection, project_id)
            project = connection.execute(
                "SELECT * FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
            if not project:
                raise KeyError(f"project not found: {project_id}")

            project_data = {
                "project_id": project["project_id"],
                "title": project["title"],
                "objective": project["objective"],
                "status": project["status"],
                "config": json.loads(project["config_json"]),
            }

            def has_successor(candidate_item_id: str) -> bool:
                return connection.execute(
                    """
                    SELECT 1 FROM research_items
                    WHERE project_id = ? AND supersedes_item_id = ?
                    LIMIT 1
                    """,
                    (project_id, candidate_item_id),
                ).fetchone() is not None

            def source_links_for_version(version_id: str) -> list[dict[str, Any]]:
                """Read only append-only links for this project's exact item version."""
                rows = connection.execute(
                    """
                    SELECT el.relation, el.verified_evidence_id,
                           COALESCE(el.passage_id, ve.passage_id) AS passage_id,
                           COALESCE(p.document_id, ve.document_id) AS document_id,
                           COALESCE(p.location_json, ve.location_json, '{}') AS location_json,
                           d.source_version
                    FROM evidence_links el
                    JOIN research_item_versions riv ON riv.version_id = el.version_id
                    JOIN research_items ri ON ri.item_id = riv.item_id
                    LEFT JOIN passages p ON p.passage_id = el.passage_id
                    LEFT JOIN verified_evidence ve
                           ON ve.verified_evidence_id = el.verified_evidence_id
                    JOIN documents d
                         ON d.document_id = COALESCE(p.document_id, ve.document_id)
                    JOIN project_sources ps
                         ON ps.document_id = d.document_id AND ps.project_id = ?
                    WHERE ri.project_id = ? AND el.version_id = ?
                    ORDER BY el.link_id
                    """,
                    (project_id, project_id, version_id),
                ).fetchall()
                links: list[dict[str, Any]] = []
                for row in rows:
                    location = json.loads(row["location_json"])
                    links.append(
                        {
                            "version_id": version_id,
                            "relation": row["relation"],
                            "passage_id": row["passage_id"],
                            "verified_evidence_id": row["verified_evidence_id"],
                            "document_id": row["document_id"],
                            "citation_locator": _citation_locator(
                                row, passage_id=row["passage_id"], location=location
                            ),
                        }
                    )
                return links

            def item_record(
                row: Any,
                payload: dict[str, Any],
                *,
                include_payload: bool = False,
                source_links: list[dict[str, Any]] | None = None,
            ) -> dict[str, Any]:
                if source_links is None:
                    source_links = source_links_for_version(row["version_id"])
                successor = has_successor(row["item_id"])
                # A client payload field named source_links is never treated as
                # authoritative. The synthetic section below is server-owned.
                available = [str(key) for key in payload.keys() if key != "source_links"]
                if source_links:
                    available.append("source_links")
                hint = payload.get("title") or payload.get("question") or payload.get("idea")
                if isinstance(hint, (dict, list)):
                    hint = None
                relation_counts: dict[str, int] = {}
                for link in source_links:
                    relation = str(link["relation"])
                    relation_counts[relation] = relation_counts.get(relation, 0) + 1
                record = {
                    "item_id": row["item_id"],
                    "kind": row["kind"],
                    "status": row["status"],
                    "supersedes_item_id": row["supersedes_item_id"],
                    "has_successor": successor,
                    "is_current": not successor,
                    "version_id": row["version_id"],
                    "updated_at": row["updated_at"],
                    "available_sections": available,
                    "source_link_count": len(source_links),
                    "source_link_relations": relation_counts,
                }
                if hint:
                    record["title_hint"] = str(hint)[:160]
                if row["kind"] == "report":
                    manifest = connection.execute(
                        """
                        SELECT report_manifest_id, report_version_id
                        FROM report_manifest
                        WHERE report_version_id = ?
                        """,
                        (row["version_id"],),
                    ).fetchone()
                    if manifest:
                        record["report_manifest_id"] = manifest["report_manifest_id"]
                        record["report_revision_id"] = manifest["report_version_id"]
                if include_payload:
                    safe_payload = dict(payload)
                    safe_payload.pop("source_links", None)
                    record["payload"] = safe_payload
                    record["payload_complete"] = True
                else:
                    record["payload_complete"] = False
                return record

            def latest_item(candidate_item_id: str) -> tuple[Any, dict[str, Any]]:
                row = connection.execute(
                    """
                    SELECT ri.*, riv.version_id, riv.payload_json, riv.created_at AS version_created_at
                    FROM research_items ri
                    JOIN research_item_versions riv ON riv.item_id = ri.item_id
                    WHERE ri.project_id = ? AND ri.item_id = ?
                      AND riv.version_no = (
                          SELECT MAX(v2.version_no) FROM research_item_versions v2
                          WHERE v2.item_id = ri.item_id
                      )
                    LIMIT 1
                    """,
                    (project_id, candidate_item_id),
                ).fetchone()
                if not row:
                    # Do not distinguish an unknown ID from an ID belonging to
                    # another project at the response boundary.
                    raise KeyError("research item not found")
                payload = json.loads(row["payload_json"])
                if not isinstance(payload, dict):
                    raise PolicyError("research item payload is invalid")
                return row, payload

            if item_id is not None:
                row, payload = latest_item(item_id)
                source_links = source_links_for_version(row["version_id"])
                record = item_record(row, payload, source_links=source_links)
                if section is not None:
                    if section == "source_links":
                        if not source_links:
                            raise PolicyError("section is not available for this research item")
                        value = source_links
                    elif section in payload and section != "source_links":
                        value = payload[section]
                    else:
                        raise PolicyError("section is not available for this research item")
                    is_text = isinstance(value, str)
                    serialized = value if is_text else _json(value)
                    total_chars = len(serialized)
                    if offset > total_chars:
                        raise PolicyError("section offset is out of range")
                    end = min(total_chars, offset + chunk_size)
                    content = serialized[offset:end]
                    next_offset = end if end < total_chars else None
                    record["section"] = {
                        "name": section,
                        "content_type": "text" if is_text else "json",
                        "content": content,
                        "offset": offset,
                        "next_offset": next_offset,
                        "total_chars": total_chars,
                    }
                    record["payload_complete"] = False
                    return {
                        "project": project_data,
                        "item_id": item_id,
                        "items": [record],
                        "available_sections": record["available_sections"],
                        "section": section,
                        "offset": offset,
                        "next_offset": next_offset,
                    }

                payload_size = len(_json(payload))
                if payload_size <= item_payload_budget:
                    record = item_record(
                        row, payload, include_payload=True, source_links=source_links
                    )
                else:
                    record["payload_size"] = payload_size
                    record["payload_available_via_sections"] = True
                return {
                    "project": project_data,
                    "item_id": item_id,
                    "items": [record],
                    "available_sections": record["available_sections"],
                }

            if cursor is not None:
                offset = _decode_context_cursor(cursor, project_id)
            rows = connection.execute(
                """
                SELECT ri.*, riv.version_id, riv.payload_json, riv.created_at AS version_created_at
                FROM research_items ri
                JOIN research_item_versions riv ON riv.item_id = ri.item_id
                WHERE ri.project_id = ?
                  AND riv.version_no = (
                      SELECT MAX(v2.version_no) FROM research_item_versions v2
                      WHERE v2.item_id = ri.item_id
                  )
                ORDER BY ri.updated_at DESC, ri.item_id
                LIMIT ? OFFSET ?
                """,
                (project_id, limit, offset),
            ).fetchall()
            total_items = connection.execute(
                "SELECT COUNT(*) FROM research_items WHERE project_id = ?", (project_id,)
            ).fetchone()[0]
            approvals = connection.execute(
                """
                SELECT request_id, target_type, item_id, verified_evidence_id,
                       rationale, created_at
                FROM approval_requests_v2
                WHERE project_id = ? AND status = 'pending'
                ORDER BY created_at LIMIT 20
                """,
                (project_id,),
            ).fetchall()
            records: list[dict[str, Any]] = []
            for row in rows:
                payload = json.loads(row["payload_json"])
                records.append(item_record(row, payload))

            # Preserve the old full response for small contexts, while making
            # the default large-context response a safe lightweight index.
            if detail == "full":
                for index, row in enumerate(rows):
                    payload = json.loads(row["payload_json"])
                    candidate = item_record(row, payload, include_payload=True)
                    trial = {
                        "project": project_data,
                        "items": records[:index] + [candidate] + records[index + 1 :],
                        "pending_approvals": [dict(item) for item in approvals],
                    }
                    if len(_json(trial)) <= safe_payload_budget:
                        records[index] = candidate

            next_offset = offset + len(rows)
            next_cursor = _context_cursor(project_id, next_offset) if next_offset < total_items else None
            approval_records = [
                {
                    "request_id": item["request_id"],
                    "target_type": item["target_type"],
                    "item_id": item["item_id"],
                    "verified_evidence_id": item["verified_evidence_id"],
                    "rationale": str(item["rationale"] or "")[:240],
                    "created_at": item["created_at"],
                }
                for item in approvals
            ]
            return {
                "project": project_data,
                "items": records,
                "pending_approvals": approval_records,
                "offset": offset,
                "limit": limit,
                "total_items": total_items,
                "has_more": next_cursor is not None,
                "next_cursor": next_cursor,
            }

    def get_report_manifest(self, *, project_id: str, item_id: str) -> dict:
        with connect(self.settings, read_only=True) as connection:
            self._require_project(connection, project_id)
            row = connection.execute(
                """
                SELECT rm.*
                FROM report_manifest rm
                JOIN research_item_versions riv ON riv.version_id = rm.report_version_id
                JOIN research_items ri ON ri.item_id = riv.item_id
                WHERE ri.project_id = ? AND ri.item_id = ?
                  AND riv.version_no = (
                      SELECT MAX(v2.version_no) FROM research_item_versions v2
                      WHERE v2.item_id = ri.item_id
                  )
                LIMIT 1
                """,
                (project_id, item_id),
            ).fetchone()
            if not row:
                raise KeyError("report manifest not found")
            return {
                "report_manifest_id": row["report_manifest_id"],
                "report_version_id": row["report_version_id"],
                "protocol_project_id": row["protocol_project_id"],
                "claim_revision_ids": json.loads(row["claim_revision_ids_json"]),
                "evidence_revision_ids": json.loads(row["evidence_revision_ids_json"]),
                "passage_revision_ids": json.loads(row["passage_revision_ids_json"]),
                "verification_event_ids": json.loads(row["verification_event_ids_json"]),
                "approval_event_ids": json.loads(row["approval_event_ids_json"]),
                "source_snapshot_ids": json.loads(row["source_snapshot_ids_json"]),
                "constraint_revision_id": row["constraint_revision_id"],
                "research_project_id": row["research_project_id"],
                "project_export_ids": json.loads(row["project_export_ids_json"]),
                "cross_project_link_ids": json.loads(row["cross_project_link_ids_json"]),
                "deliverable_layer": row["deliverable_layer"],
                "artifact_profile": row["artifact_profile"],
                "writing_policy_id": row["writing_policy_id"],
                "writing_policy_version": row["writing_policy_version"],
                "writing_policy_snapshot": (
                    json.loads(row["writing_policy_snapshot_json"])
                    if row["writing_policy_snapshot_json"] is not None
                    else None
                ),
                "compression_review_status": row["compression_review_status"],
                "writing_audit_summary": (
                    json.loads(row["writing_audit_summary_json"])
                    if row["writing_audit_summary_json"] is not None
                    else None
                ),
                "created_by": row["created_by"],
                "created_at": row["created_at"],
            }

    def get_search_history(self, *, project_id: str, limit: int = 20) -> dict:
        limit = bounded_int(limit, minimum=1, maximum=100, name="limit")
        with connect(self.settings, read_only=True) as connection:
            self._require_project(connection, project_id)
            rows = connection.execute(
                """
                SELECT event_id, query_text, parameters_json, result_ids_json, created_at
                FROM search_events
                WHERE project_id = ? AND session_id = ?
                ORDER BY event_id DESC LIMIT ?
                """,
                (project_id, self.actor.session_id, limit),
            ).fetchall()
        return {
            "project_id": project_id,
            "session_id": self.actor.session_id,
            "events": [
                {
                    "event_id": row["event_id"],
                    "query": row["query_text"],
                    "parameters": json.loads(row["parameters_json"]),
                    "result_ids": json.loads(row["result_ids_json"]),
                    "created_at": row["created_at"],
                }
                for row in rows
            ],
        }

