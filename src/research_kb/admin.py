from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings
from .db import SCHEMA_VERSION, audit, connect, migrate, transaction
from .ingest import ingest_manifest
from .policy import Actor, PolicyError, require_admin
from .search import rebuild_search_index_in_connection
from .service import ResearchService, _json


_METADATA_FIELDS = {
    "title",
    "creator",
    "source_type",
    "language",
    "source_date",
    "source_version",
    "source_name",
    "reliability_status",
    "verification_status",
    "metadata_json",
}
_RELIABILITY = {"unknown", "unverified", "reviewed", "authoritative"}
_VERIFICATION = {"unverified", "partially_verified", "verified"}
_PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class AdminService:
    def __init__(self, settings: Settings, actor: Actor):
        require_admin(actor)
        self.settings = settings
        self.actor = actor
        self.research = ResearchService(settings, actor)

    def initialize(self) -> None:
        migrate(self.settings)

    def status(self) -> dict:
        return self.research.status()

    def create_project(self, *, project_id: str, title: str, objective: str) -> dict:
        if not _PROJECT_ID.fullmatch(project_id):
            raise PolicyError("project_id must contain only letters, numbers, _, ., or -")
        title = str(title or "").strip()
        objective = str(objective or "").strip()
        if not title or not objective:
            raise PolicyError("title and objective are required")
        if len(title) > 300 or len(objective) > 4000:
            raise PolicyError("project fields exceed configured limits")
        with transaction(self.settings) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO projects(project_id, title, objective, status, config_json, created_at)
                    VALUES (?, ?, ?, 'active', '{}', datetime('now'))
                    """,
                    (project_id, title, objective),
                )
            except sqlite3.IntegrityError as exc:
                raise PolicyError("project_id already exists") from exc
            result = {"project_id": project_id, "status": "active"}
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=project_id,
                operation="project_create", parameters={"project_id": project_id}, result=result,
            )
            return result

    def list_projects(self) -> dict:
        with connect(self.settings, read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT project_id, title, objective, status, created_at
                FROM projects ORDER BY created_at, project_id
                """
            ).fetchall()
        return {"projects": [dict(row) for row in rows]}

    def archive_project(self, *, project_id: str) -> dict:
        with transaction(self.settings) as connection:
            row = connection.execute(
                "SELECT status FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
            if not row:
                raise PolicyError("project not found")
            if row["status"] != "active":
                raise PolicyError("project is already archived")
            connection.execute(
                "UPDATE projects SET status = 'archived' WHERE project_id = ?", (project_id,)
            )
            result = {"project_id": project_id, "status": "archived"}
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=project_id,
                operation="project_archive", parameters={"project_id": project_id}, result=result,
            )
            return result

    def ingest(self, *, project_id: str, manifest_path: str | Path, dry_run: bool = False) -> dict:
        return ingest_manifest(
            self.settings, self.actor, manifest_path, project_id=project_id, dry_run=dry_run
        )

    def metadata_show(self, *, project_id: str, document_id: str) -> dict:
        return self.research.get_document_metadata(project_id=project_id, document_id=document_id)

    def metadata_update(
        self,
        *,
        project_id: str,
        document_id: str,
        updates: dict[str, Any],
        reason: str,
    ) -> dict:
        reason = str(reason or "").strip()
        if not reason:
            raise PolicyError("metadata update reason is required")
        unknown = set(updates) - _METADATA_FIELDS
        if unknown:
            raise PolicyError(f"unsupported metadata fields: {sorted(unknown)}")
        if not updates:
            raise PolicyError("metadata update requires at least one field")
        with transaction(self.settings) as connection:
            self.research._require_project(connection, project_id)
            row = connection.execute(
                """
                SELECT d.*
                FROM documents d
                JOIN project_sources ps ON ps.document_id = d.document_id
                WHERE d.document_id = ? AND ps.project_id = ?
                """,
                (document_id, project_id),
            ).fetchone()
            if not row:
                raise PolicyError("document is outside project scope")
            old = {
                field: row[field]
                for field in _METADATA_FIELDS
                if field != "metadata_json"
            }
            old["metadata_json"] = json.loads(row["metadata_json"])
            new = dict(old)
            for field, value in updates.items():
                if field == "metadata_json":
                    if not isinstance(value, dict):
                        raise PolicyError("metadata_json must be an object")
                    new[field] = value
                else:
                    new[field] = None if value is None else str(value).strip()
            for required_field in ("title", "source_type", "language", "source_name"):
                if not isinstance(new[required_field], str) or not new[required_field]:
                    raise PolicyError(f"{required_field} must not be empty")
            if new["reliability_status"] not in _RELIABILITY:
                raise PolicyError("invalid reliability_status")
            if new["verification_status"] not in _VERIFICATION:
                raise PolicyError("invalid verification_status")
            if new == old:
                return {"document_id": document_id, "changed": False, "reason": reason}

            assignments = []
            parameters: list[Any] = []
            for field in updates:
                assignments.append(f"{field} = ?")
                value = new[field]
                parameters.append(
                    json.dumps(value, ensure_ascii=False, sort_keys=True)
                    if field == "metadata_json" else value
                )
            parameters.append(document_id)
            connection.execute(
                f"UPDATE documents SET {', '.join(assignments)} WHERE document_id = ?",
                parameters,
            )
            connection.execute(
                """
                INSERT INTO source_metadata_audit(
                    document_id, old_values_json, new_values_json, reason,
                    actor_id, actor_kind, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    document_id, _json(old), _json(new), reason,
                    self.actor.actor_id, self.actor.actor_kind,
                ),
            )
            result = {"document_id": document_id, "changed": True, "reason": reason}
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=project_id,
                operation="metadata_update", parameters={"document_id": document_id, "fields": sorted(updates)}, result=result,
            )
            return result

    def list_approvals(self, *, project_id: str | None = None, status: str | None = None) -> dict:
        if status is not None and status not in {"pending", "approved", "rejected"}:
            raise PolicyError("invalid approval status")
        with connect(self.settings, read_only=True) as connection:
            conditions = []
            parameters: list[Any] = []
            if project_id:
                self.research._require_project(connection, project_id)
                conditions.append("project_id = ?")
                parameters.append(project_id)
            if status:
                conditions.append("status = ?")
                parameters.append(status)
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            rows = connection.execute(
                f"""
                SELECT request_id, project_id, target_type, item_id,
                       verified_evidence_id, requested_by, status, rationale,
                       decided_by, decision_note, created_at, decided_at
                FROM approval_requests_v2{where}
                ORDER BY created_at, request_id
                """,
                parameters,
            ).fetchall()
        return {"approvals": [dict(row) for row in rows]}

    def decide_approval(self, *, request_id: str, approve: bool, note: str = "") -> dict:
        return self.research.decide_approval(request_id=request_id, approve=approve, note=note)

    def backup(self, *, output: str | Path | None = None) -> dict:
        destination = (
            Path(output).expanduser()
            if output
            else self.settings.workspace / "backups" / (
                "research-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".db"
            )
        ).resolve()
        live = self.settings.database.resolve()
        if destination == live:
            raise PolicyError("backup destination must differ from the live database")
        if destination.exists():
            try:
                if destination.samefile(live):
                    raise PolicyError("backup destination must differ from the live database")
            except FileNotFoundError:
                pass
            if destination.is_dir():
                raise PolicyError("backup destination must be a file")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        try:
            with connect(self.settings, read_only=True) as source:
                target = sqlite3.connect(temporary)
                try:
                    source.backup(target)
                    target.execute("PRAGMA foreign_keys = ON")
                    integrity = target.execute("PRAGMA quick_check").fetchone()[0]
                    foreign_keys = target.execute("PRAGMA foreign_keys").fetchone()[0]
                    target.commit()
                finally:
                    target.close()
            if integrity != "ok" or foreign_keys != 1:
                raise PolicyError("backup integrity check failed")
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        return {
            "backup": str(destination),
            "quick_check": integrity,
            "foreign_keys": foreign_keys,
        }

    def restore(self, *, backup_path: str | Path, output: str | Path) -> dict:
        source_path = Path(backup_path).expanduser().resolve(strict=True)
        destination = Path(output).expanduser().resolve()
        live = self.settings.database.resolve()
        if not source_path.is_file():
            raise PolicyError("restore source must be a regular file")
        if source_path == destination or destination == live:
            raise PolicyError("restore output must be a separate path")
        if destination.exists():
            raise PolicyError("restore output already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        integrity = "error"
        foreign_keys = 0
        schema_version = None
        counts: dict[str, int] = {}
        try:
            source = sqlite3.connect(f"file:{source_path.as_posix()}?mode=ro", uri=True)
            target = sqlite3.connect(temporary)
            try:
                source.execute("PRAGMA query_only = ON")
                source.execute("PRAGMA foreign_keys = ON")
                source_check = source.execute("PRAGMA quick_check").fetchone()[0]
                if source_check != "ok":
                    raise PolicyError("restore source quick_check failed")
                source.backup(target)
                target.execute("PRAGMA foreign_keys = ON")
                integrity = target.execute("PRAGMA quick_check").fetchone()[0]
                foreign_keys = target.execute("PRAGMA foreign_keys").fetchone()[0]
                schema_version = target.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                ).fetchone()[0]
                for table in (
                    "projects", "documents", "passages", "research_items",
                    "verified_evidence", "audit_log", "passages_search_fts",
                ):
                    counts[table] = target.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                target.commit()
            finally:
                source.close()
                target.close()
            if integrity != "ok" or foreign_keys != 1 or schema_version != SCHEMA_VERSION:
                raise PolicyError("restored database integrity or schema check failed")
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        return {
            "restore": str(destination),
            "quick_check": integrity,
            "foreign_keys": foreign_keys,
            "schema_version": schema_version,
            "counts": counts,
        }

    def cleanup_expired_tokens(self) -> dict:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with transaction(self.settings) as connection:
            updated = connection.execute(
                """
                UPDATE verification_tokens
                SET consumed_at = ?
                WHERE consumed_at IS NULL AND expires_at < ?
                """,
                (now, now),
            ).rowcount
            result = {"expired_tokens_marked": updated}
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=None,
                operation="cleanup_expired_tokens", parameters={}, result=result,
            )
            return result

    def reindex(self) -> dict:
        with transaction(self.settings) as connection:
            count = rebuild_search_index_in_connection(connection)
            passage_count = connection.execute("SELECT COUNT(*) FROM passages").fetchone()[0]
            indexed_count = connection.execute("SELECT COUNT(*) FROM passages_search_fts").fetchone()[0]
            if indexed_count != passage_count:
                raise PolicyError("reindex count does not match passages")
            result = {"passages": passage_count, "indexed": indexed_count}
            audit(
                connection, actor_id=self.actor.actor_id, actor_kind=self.actor.actor_kind,
                session_id=self.actor.session_id, project_id=None,
                operation="reindex", parameters={}, result=result,
            )
            return result