"""Shared, dependency-free checkpoint identity predicates."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


CHECKPOINT_SCHEMA = "research-checkpoint/v1"
CHECKPOINT_VERSION = 1


def is_standard_checkpoint_payload(payload: Any) -> bool:
    """Return whether a latest item payload carries the standard schema marker.

    The schema marker is the compatibility discriminator for historical
    records.  Newly created records additionally carry
    ``checkpoint_version == CHECKPOINT_VERSION``; older schema-marked records
    remain recognizable and are never rewritten by this predicate.
    """

    return isinstance(payload, Mapping) and payload.get("schema") == CHECKPOINT_SCHEMA
