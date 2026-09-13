from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "writing"


class LegacyGoldenTests(unittest.TestCase):
    def _load(self, name: str) -> dict:
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    def assert_counts_match_summary(self, fixture: dict) -> None:
        summary = fixture["summary"]
        for bucket in ("errors", "warnings", "review_items", "approval_blockers"):
            self.assertIsInstance(fixture[bucket], list)
            self.assertEqual(len(fixture[bucket]), summary[bucket], bucket)

    def assert_items_have_rule_ids(self, fixture: dict) -> None:
        for bucket in ("errors", "warnings", "review_items", "approval_blockers"):
            for item in fixture[bucket]:
                self.assertIsInstance(item, dict)
                self.assertIsInstance(item.get("rule_id"), str)
                self.assertTrue(item["rule_id"])

    def test_fixture_structure(self) -> None:
        for name in ("legacy-v62.json", "legacy-v63.json"):
            fixture = self._load(name)
            self.assertEqual(fixture["legacy_audit"], "audit_lite")
            self.assertIn(fixture["profile"], ("legacy_v62", "legacy_v63"))
            self.assertEqual(fixture["legacy_version"], "v" + fixture["profile"][-1] + "." + fixture["profile"][-1] if False else "v6." + fixture["profile"][-1])
            self.assertEqual(fixture["summary"]["errors"], 0)
            self.assertEqual(fixture["summary"]["warnings"], 7)
            self.assertEqual(fixture["summary"]["review_items"], 6)
            self.assertEqual(fixture["summary"]["approval_blockers"], 3)
            self.assert_counts_match_summary(fixture)
            self.assert_items_have_rule_ids(fixture)

    def test_v62_semantics_are_stable(self) -> None:
        fixture = self._load("legacy-v62.json")
        self.assertEqual(fixture["files"]["links"], 102)
        self.assertEqual(fixture["files"]["events"], 29)
        objects = [item["object"] for item in fixture["warnings"]]
        self.assertEqual(
            objects,
            [
                "link-map-v6.2-ch1-claim-i1",
                "link-map-v6.2-ch2-claim-i2",
                "link-map-v6.2-ch3-claim-i3",
                "link-map-v6.2-ch4-claim-i4",
                "link-map-v6.2-ch5-claim-i5",
                "link-map-v6.2-adorno-claim-i6",
                "link-map-v6.2-ch6-claim-i5",
            ],
        )
        self.assertEqual(
            [item["rule_id"] for item in fixture["review_items"]],
            ["weak_bridge", "retained_stale_link", "retained_stale_link", "retained_stale_link", "research_history", "second_nature_bridge"],
        )
        self.assertEqual(
            [item["rule_id"] for item in fixture["approval_blockers"]],
            ["center_thesis_pending", "pending_page", "final_approval_pending"],
        )

    def test_v63_semantics_are_stable(self) -> None:
        fixture = self._load("legacy-v63.json")
        self.assertEqual(fixture["files"]["links"], 143)
        self.assertEqual(fixture["files"]["events"], 7)
        objects = [item["object"] for item in fixture["warnings"]]
        self.assertEqual(
            objects,
            [
                "link-map-v6.3-ch1-claim-p1",
                "link-map-v6.3-ch2-claim-p3",
                "link-map-v6.3-ch3-claim-p5",
                "link-map-v6.3-ch4-claim-p6",
                "link-map-v6.3-ch5-claim-p8",
                "link-map-v6.3-ch6-claim-i5",
                "link-map-v6.3-adorno-claim-p11",
            ],
        )
        self.assertEqual(
            [item["rule_id"] for item in fixture["review_items"]],
            ["weak_bridge", "retained_stale_link", "retained_stale_link", "retained_stale_link", "research_history", "second_nature_bridge"],
        )
        self.assertEqual(
            [item["rule_id"] for item in fixture["approval_blockers"]],
            ["center_thesis_pending", "pending_page", "final_approval_pending"],
        )

    def test_shared_review_semantics(self) -> None:
        for name in ("legacy-v62.json", "legacy-v63.json"):
            fixture = self._load(name)
            weak = [item for item in fixture["review_items"] if item["rule_id"] == "weak_bridge"]
            self.assertEqual(len(weak), 1)
            self.assertEqual(weak[0]["object"], "link-bridge-B2-ethical-political")
            stale = [item for item in fixture["review_items"] if item["rule_id"] == "retained_stale_link"]
            self.assertEqual(len(stale), 3)
            blocked = [item for item in fixture["approval_blockers"] if item["rule_id"] == "center_thesis_pending"]
            self.assertEqual(blocked[0]["human_status"], "pending")


if __name__ == "__main__":
    unittest.main()
