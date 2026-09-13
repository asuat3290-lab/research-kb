"""Admin-facing facade for Max Research control commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..policy import Actor
from .service import MaxControlService


class MaxAdminService(MaxControlService):
    """Named facade used by the Admin CLI and integration callers."""

    def __init__(self, database: str | Path, actor: Actor, **kwargs: Any) -> None:
        super().__init__(database, actor, **kwargs)


__all__ = ["MaxAdminService"]
