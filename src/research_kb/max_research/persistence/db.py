"""SQLite boundary for the independent Max Research control store."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

from ..contract import canonical_json, canonical_sha256
from .migrations import apply_migrations, validate_schema_ledger
from .schema_manifest import SchemaManifestError, verify_schema_manifest
from .version import CONTROL_SCHEMA_VERSION


# Max control schema is intentionally independent from the core research DB
# schema (which remains 5).  MR-2B0 adds provider/grant/scheduler tables as
# migration 006 without changing any core migration.
class MaxControlError(RuntimeError):
    """Safe, user-facing control-plane failure."""

    def __init__(self, message: str, *, error_code: str | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class MaxControlNotInitialized(MaxControlError):
    """Raised by read-only operations before explicit ``max init``."""


@dataclass(frozen=True)
class MaxResearchSettings:
    database: Path
    busy_timeout_ms: int = 5000

    @classmethod
    def from_path(cls, path: str | Path, *, busy_timeout_ms: int = 5000) -> "MaxResearchSettings":
        value = Path(path).expanduser()
        if not value.is_absolute():
            value = (Path.cwd() / value).resolve()
        else:
            value = value.resolve()
        if busy_timeout_ms < 1 or busy_timeout_ms > 120_000:
            raise MaxControlError("busy timeout is outside the supported range")
        return cls(value, busy_timeout_ms)


def _read_only_uri(path: Path) -> str:
    return f"file:{quote(path.as_posix(), safe='/')}?mode=ro"


def connect_control_db(
    settings: MaxResearchSettings | str | Path,
    *,
    read_only: bool = False,
) -> sqlite3.Connection:
    value = settings if isinstance(settings, MaxResearchSettings) else MaxResearchSettings.from_path(settings)
    path = value.database
    if read_only:
        if not path.is_file():
            raise MaxControlNotInitialized("Max control database is not initialized; run max init explicitly")
        connection = sqlite3.connect(
            _read_only_uri(path), uri=True, timeout=value.busy_timeout_ms / 1000.0,
            isolation_level=None,
        )
    else:
        connection = sqlite3.connect(
            str(path), timeout=value.busy_timeout_ms / 1000.0, isolation_level=None,
        )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {int(value.busy_timeout_ms)}")
    if read_only:
        connection.execute("PRAGMA query_only = ON")
    else:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
    return connection


@contextlib.contextmanager
def control_transaction(
    connection: sqlite3.Connection, *, immediate: bool = True
) -> Iterator[sqlite3.Connection]:
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def initialize_control_db(
    settings: MaxResearchSettings | str | Path,
    *,
    fixture: bool = False,
) -> dict[str, int | bool]:
    value = settings if isinstance(settings, MaxResearchSettings) else MaxResearchSettings.from_path(settings)
    value.database.parent.mkdir(parents=True, exist_ok=True)
    created_for_fixture = False
    initialized_ok = False
    if fixture:
        # Fixture authority is a creation-time property.  Refuse every
        # pre-existing path, including an empty file, a SQLite header, an old
        # schema, and a production Max database.  O_EXCL makes concurrent
        # fixture creators race on the filesystem before either can migrate.
        try:
            fd = os.open(str(value.database), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            created_for_fixture = True
        except FileExistsError as exc:
            raise MaxControlError("fixture control database must be created exactly once") from exc
        except OSError as exc:
            raise MaxControlError("fixture control database could not be created") from exc
    connection = None
    try:
        # Existing databases are preflighted read-only before the writable
        # connection can change SQLite journal pragmas or apply migrations.
        if value.database.exists() and not created_for_fixture:
            preflight = connect_control_db(value, read_only=True)
            try:
                try:
                    validate_schema_ledger(preflight)
                except Exception as exc:
                    raise MaxControlError("Max control migration ledger is not accepted by this release") from exc
            finally:
                preflight.close()
        connection = connect_control_db(value, read_only=False)
        version = apply_migrations(connection)
        schema_check = verify_schema_manifest(connection)
        if not schema_check["ok"]:
            raise MaxControlError("Max control database schema manifest verification failed")
        if created_for_fixture:
            marker = {
                "marker_id": "fixture-control-db",
                "marker_kind": "fixture-control-db",
                "fixture_identity": "research-kb-mr2a-fixture/v1",
                "authority_id": "fixture-authority",
            }
            marker_hash = canonical_sha256(marker)
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT marker_json, marker_hash FROM max_fixture_control_markers WHERE marker_id=?",
                    (marker["marker_id"],),
                ).fetchone()
                if existing is not None and (existing["marker_json"] != canonical_json(marker) or existing["marker_hash"] != marker_hash):
                    raise MaxControlError("fixture control marker collision")
                if existing is None:
                    connection.execute(
                        "INSERT INTO max_fixture_control_markers(marker_id, marker_kind, fixture_identity, authority_id, marker_json, marker_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                        (marker["marker_id"], marker["marker_kind"], marker["fixture_identity"], marker["authority_id"], canonical_json(marker), marker_hash),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
        if quick_check != "ok" or foreign_keys != 1:
            raise MaxControlError("Max control database integrity check failed")
        initialized_ok = True
        return {
            "initialized": True,
            "schema_version": version,
            "quick_check": quick_check == "ok",
            "foreign_keys": foreign_keys == 1,
            "fixture": bool(created_for_fixture or connection.execute("SELECT 1 FROM max_fixture_control_markers WHERE marker_id='fixture-control-db'").fetchone()),
        }
    finally:
        if connection is not None:
            connection.close()
        if created_for_fixture:
            try:
                # Only remove the file this invocation created.  This is
                # recovery for a failed first migration and never targets an
                # existing user database.
                if value.database.exists() and not initialized_ok:
                    value.database.unlink()
            except OSError:
                pass


__all__ = [
    "CONTROL_SCHEMA_VERSION",
    "MaxControlError",
    "MaxControlNotInitialized",
    "MaxResearchSettings",
    "connect_control_db",
    "control_transaction",
    "initialize_control_db",
]
