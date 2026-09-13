from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import Settings


_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]+)_[^/]+\.sql$")


def migration_paths() -> tuple[tuple[int, Path], ...]:
    migration_dir = Path(__file__).with_name("migrations")
    migrations: list[tuple[int, Path]] = []
    for path in migration_dir.glob("*.sql"):
        match = _MIGRATION_NAME.match(path.name)
        if not match:
            continue
        migrations.append((int(match.group("version")), path))
    migrations.sort(key=lambda item: item[0])
    versions = [version for version, _ in migrations]
    if len(versions) != len(set(versions)):
        raise RuntimeError("migration versions must be unique")
    if not migrations:
        raise RuntimeError("no database migrations were found")
    return tuple(migrations)


SCHEMA_VERSION = migration_paths()[-1][0]


class ClosingConnection(sqlite3.Connection):
    """Commit or roll back on context exit, then release the database handle."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect(
    settings: Settings,
    *,
    read_only: bool = False,
    immutable: bool = False,
) -> sqlite3.Connection:
    if immutable and not read_only:
        raise ValueError("immutable connections must be read-only")
    if read_only:
        query = "mode=ro" + ("&immutable=1" if immutable else "")
        connection = sqlite3.connect(
            f"file:{settings.database.as_posix()}?{query}",
            uri=True,
            timeout=30,
            factory=ClosingConnection,
        )
        connection.execute("PRAGMA query_only = ON")
    else:
        settings.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            settings.database,
            timeout=30,
            factory=ClosingConnection,
        )
        connection.execute("PRAGMA journal_mode = WAL")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


@contextmanager
def transaction(settings: Settings) -> Iterator[sqlite3.Connection]:
    connection = connect(settings)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _applied_versions(connection: sqlite3.Connection) -> set[int]:
    try:
        return {
            int(row[0])
            for row in connection.execute("SELECT version FROM schema_migrations")
        }
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return set()
        raise


def _apply_migration(
    connection: sqlite3.Connection,
    version: int,
    path: Path,
) -> None:
    sql = path.read_text(encoding="utf-8")
    script = (
        "BEGIN IMMEDIATE;\n"
        + sql
        + "\nINSERT OR IGNORE INTO schema_migrations(version, applied_at) "
        + f"VALUES ({version}, datetime('now'));\n"
        + "COMMIT;\n"
    )
    try:
        connection.executescript(script)
    except Exception:
        connection.rollback()
        raise


def migrate(settings: Settings) -> None:
    settings.workspace.mkdir(parents=True, exist_ok=True)
    for root in settings.corpus_roots:
        root.mkdir(parents=True, exist_ok=True)
    with connect(settings) as connection:
        applied = _applied_versions(connection)
        for version, path in migration_paths():
            if version not in applied:
                _apply_migration(connection, version, path)
                applied.add(version)

        connection.execute(
            """
            INSERT OR IGNORE INTO projects(
                project_id, title, objective, status, config_json, created_at
            ) VALUES ('default', 'Default research project',
                      'General local-source research', 'active', '{}', datetime('now'))
            """
        )
        from .search import rebuild_search_index_in_connection

        rebuild_search_index_in_connection(connection)
        connection.commit()


def audit(
    connection: sqlite3.Connection,
    *,
    actor_id: str,
    actor_kind: str,
    session_id: str,
    project_id: str | None,
    operation: str,
    parameters: dict,
    result: dict,
    success: bool = True,
) -> None:
    connection.execute(
        """
        INSERT INTO audit_log(
            actor_id, actor_kind, session_id, project_id, operation,
            parameters_json, result_json, success, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
        (
            actor_id,
            actor_kind,
            session_id,
            project_id,
            operation,
            json.dumps(parameters, ensure_ascii=False, sort_keys=True),
            json.dumps(result, ensure_ascii=False, sort_keys=True),
            1 if success else 0,
        ),
    )
