"""Historical schema-21 compatibility boundary for MR-4B1B-v12R1.

The former 32-test class was split in MR-4B1B-v14R0T.  Only this physical
schema-21 compatibility assertion remains here; current behavior invariants
live in ``test_max_research_mr4b1b_v14r0t_current.py`` and run on schema 22
without a skip guard or an official historical database dependency.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from research_kb.max_research.persistence.version import CONTROL_SCHEMA_VERSION


V11_DB = Path(
    os.environ.get(
        "MR4B1B_V11_DB",
        r"D:\research-kb-canary\control\max-canary-v11-preview.db",
    )
)
PILOT_DB = Path(
    os.environ.get("MR4B1B_PILOT_DB", r"D:\research-kb-pilot\data\research.db")
)


@unittest.skipUnless(
    V11_DB.is_file() and PILOT_DB.is_file() and CONTROL_SCHEMA_VERSION == 21,
    "historical schema-21 compatibility fixture is not executed by the current schema-22 runtime",
)
class HistoricalSchema21Tests(unittest.TestCase):
    """Read-only historical boundary; never current production coverage."""

    def test_schema21_fixture_is_explicitly_historical(self) -> None:
        self.assertEqual(CONTROL_SCHEMA_VERSION, 21)
        self.assertTrue(V11_DB.is_file())
        self.assertTrue(PILOT_DB.is_file())


if __name__ == "__main__":
    unittest.main()
