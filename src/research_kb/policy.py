from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .config import Settings


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Actor:
    actor_id: str
    session_id: str
    actor_kind: str = "agent"
    role: str = "researcher"
    framework: str = "unknown"
    model: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.actor_kind == "user" and self.role == "admin"


def require_admin(actor: Actor) -> None:
    if not actor.is_admin:
        raise PolicyError("this operation is available only to the human admin CLI")


def bounded_int(value: int, *, minimum: int, maximum: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise PolicyError(f"{name} must be between {minimum} and {maximum}")
    return value


def validate_query(settings: Settings, query: str) -> str:
    return validate_text(query, "query", settings.limits.max_query_chars)




_WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul", "clock$",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def validate_text(value: object, name: str, maximum: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"{name} must be a string")
    if "\x00" in value or any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise PolicyError(f"{name} contains an invalid Unicode character")
    clean = value.strip()
    if required and not clean:
        raise PolicyError(f"{name} must not be empty")
    if len(clean) > maximum:
        raise PolicyError(f"{name} exceeds configured character limit")
    return clean


def _validate_path_input(supplied: str | Path) -> None:
    try:
        raw = os.fspath(supplied)
    except TypeError as exc:
        raise PolicyError("source path must be a string or path") from exc
    if not isinstance(raw, str):
        raise PolicyError("source path must be text")
    if "\x00" in raw or any(0xD800 <= ord(character) <= 0xDFFF for character in raw):
        raise PolicyError("source path contains an invalid Unicode character")
    lowered = raw.casefold()
    if lowered.startswith(("file://", "http://", "https://")):
        raise PolicyError("source path must be a local filesystem path")
    if os.name != "nt":
        return
    normalized = raw.replace("/", "\\")
    if normalized.casefold().startswith(("\\\\?\\", "\\\\.\\")):
        raise PolicyError("Windows device paths are not allowed")
    if len(normalized) >= 2 and normalized[1] == ":":
        if len(normalized) == 2 or normalized[2] != "\\":
            raise PolicyError("drive-relative paths are not allowed")
    for index, component in enumerate(normalized.split("\\")):
        if not component or (index == 0 and len(component) == 2 and component[1] == ":"):
            continue
        if ":" in component:
            raise PolicyError("alternate data streams are not allowed")
        if component.rstrip(" .") != component:
            raise PolicyError("Windows path components may not end with a space or period")
        stem = component.split(".", 1)[0].casefold()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise PolicyError("reserved Windows device names are not allowed")


def _is_link_like(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def resolve_corpus_file(settings: Settings, supplied: str | Path) -> Path:
    _validate_path_input(supplied)
    try:
        lexical = Path(supplied).expanduser().absolute()
        if not lexical.exists() or not lexical.is_file():
            raise PolicyError(f"source file does not exist: {lexical}")
        for root in settings.corpus_roots:
            root_path = root.expanduser().absolute()
            if not root_path.exists() or not root_path.is_dir():
                raise PolicyError(f"configured corpus root does not exist: {root_path}")
            if _is_link_like(root_path):
                raise PolicyError("corpus roots must not be symbolic links or junctions")
            allowed = root_path.resolve(strict=True)
            try:
                relative = lexical.relative_to(allowed)
            except ValueError:
                continue
            cursor = allowed
            for part in relative.parts:
                cursor = cursor / part
                if _is_link_like(cursor):
                    raise PolicyError("links and junctions are not allowed in corpus paths")
            resolved = lexical.resolve(strict=True)
            try:
                resolved.relative_to(allowed)
            except ValueError as exc:
                raise PolicyError("source path escapes the configured corpus root") from exc
            return resolved
        raise PolicyError("source file is outside configured corpus roots")
    except PolicyError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise PolicyError("source path is invalid or inaccessible") from exc

def enforce_session_quota(connection, settings: Settings, actor: Actor, kind: str) -> None:
    if actor.is_admin:
        return
    if kind == "search":
        count = connection.execute(
            "SELECT COUNT(*) FROM search_events WHERE session_id = ?", (actor.session_id,)
        ).fetchone()[0]
        limit = settings.limits.max_searches_per_session
    else:
        count = connection.execute(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE session_id = ? AND operation LIKE 'submit_%' AND success = 1
            """,
            (actor.session_id,),
        ).fetchone()[0]
        limit = settings.limits.max_writes_per_session
    if count >= limit:
        raise PolicyError(f"session {kind} quota exceeded ({limit})")

