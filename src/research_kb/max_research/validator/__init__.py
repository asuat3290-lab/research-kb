"""Compatibility facade for MR-0 validator imports.

Keeping this module separate lets a future runner depend on validators without
depending on persistence or on the contract model implementation details.
"""

from ..contract.base import ContractValidationError, ValidationIssue, ValidationResult
from ..contract.validator import *  # noqa: F401,F403

__all__ = [
    "ContractValidationError",
    "ValidationIssue",
    "ValidationResult",
    *[name for name in globals() if not name.startswith("_")],
]
