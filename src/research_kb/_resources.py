"""Installation-safe access to research-kb runtime resources.

Resources are deliberately loaded through ``importlib.resources`` so an
installed wheel or sdist behaves the same as a source checkout.  Errors are
kept intentionally generic: callers must not expose paths, SQL, or package
layout details to users.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any


class PackagedResourceError(RuntimeError):
    """A required packaged resource is missing or malformed."""


def read_resource_text(*parts: str) -> str:
    """Read a required UTF-8 text resource from the installed package."""

    try:
        resource = resources.files("research_kb")
        for part in parts:
            resource = resource.joinpath(part)
        return resource.read_text(encoding="utf-8")
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        raise PackagedResourceError("required packaged resource is unavailable") from exc


def read_resource_bytes(*parts: str) -> bytes:
    """Read a required binary resource from the installed package."""

    try:
        resource = resources.files("research_kb")
        for part in parts:
            resource = resource.joinpath(part)
        return resource.read_bytes()
    except (OSError, TypeError, ValueError) as exc:
        raise PackagedResourceError("required packaged resource is unavailable") from exc


def read_json_resource(*parts: str) -> dict[str, Any]:
    """Read and minimally validate a required JSON object resource."""

    try:
        value = json.loads(read_resource_text(*parts))
    except PackagedResourceError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PackagedResourceError("required packaged JSON resource is invalid") from exc
    if not isinstance(value, dict):
        raise PackagedResourceError("required packaged JSON resource is invalid")
    return value


def resource_traversable(*parts: str):
    """Return a required traversable directory/file without exposing paths."""

    try:
        resource = resources.files("research_kb")
        for part in parts:
            resource = resource.joinpath(part)
        if not resource.is_dir():
            raise PackagedResourceError("required packaged resource directory is unavailable")
        return resource
    except PackagedResourceError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise PackagedResourceError("required packaged resource directory is unavailable") from exc


__all__ = [
    "PackagedResourceError",
    "read_json_resource",
    "read_resource_bytes",
    "read_resource_text",
    "resource_traversable",
]
