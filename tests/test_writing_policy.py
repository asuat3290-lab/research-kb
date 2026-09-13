from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from research_kb.policy import PolicyError
from research_kb.writing_policy import (
    COMPRESSION_REVIEW_STATUSES,
    KNOWN_PROFILES,
    SUPPORTED_LAYERS,
    load_policy_schema,
    load_writing_policy,
    resolve_submission_policy,
    resolve_writing_policy,
    validate_writing_audit_summary,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_POLICY = REPO_ROOT / "docs" / "writing-policy.md"


class WritingPolicyConfigTests(unittest.TestCase):
    def test_policy_json_is_valid_and_matches_schema(self) -> None:
        policy = load_writing_policy()
        schema = load_policy_schema()
        self.assertEqual(policy["policy_id"], "default-writing-policy")
        self.assertEqual(policy["policy_version"], "1.2.0")
        self.assertEqual(policy["schema_version"], "1")
        self.assertIn("policy_id", schema["required"])
        self.assertIn("policy_version", schema["required"])
        self.assertIn("profiles", schema["required"])
        self.assertIn("rules", schema["required"])
        self.assertIn("line_endings", schema["required"])
        self.assertEqual(policy["line_endings"]["default"], "lf")
        self.assertEqual(policy["line_endings"]["mixed_severity"], "error")

    def test_docs_policy_version_matches_json(self) -> None:
        text = DOCS_POLICY.read_text(encoding="utf-8")
        policy = load_writing_policy()
        doc_id = re.search(r"policy_id:\s*([\w.-]+)", text)
        doc_version = re.search(r"policy_version:\s*([\w.-]+)", text)
        self.assertIsNotNone(doc_id)
        self.assertIsNotNone(doc_version)
        self.assertEqual(doc_id.group(1), policy["policy_id"])
        self.assertEqual(doc_version.group(1), policy["policy_version"])

    def test_resolve_default_academic_profile(self) -> None:
        snapshot = resolve_writing_policy(profile="academic_paper")
        self.assertEqual(snapshot["profile"], "academic_paper")
        self.assertEqual(snapshot["deliverable_layer"], "A")
        self.assertEqual(snapshot["policy_id"], "default-writing-policy")
        self.assertGreaterEqual(snapshot["budget"]["min_chars"], 40000)
        self.assertEqual(snapshot["budget"]["max_chars"], 55000)
        self.assertTrue(snapshot["rules"])
        self.assertEqual(snapshot["line_endings"]["default"], "lf")
        self.assertEqual(snapshot["line_endings"]["mixed_severity"], "error")
        self.assertEqual(snapshot["_meta"]["inheritance"][-1], "report_manifest_config")

    def test_project_override_budget_and_extra_terms(self) -> None:
        snapshot = resolve_writing_policy(
            profile="academic_paper",
            project_config={"writing_policy": {"budget": {"max_chars": 60000}}},
        )
        self.assertEqual(snapshot["budget"]["max_chars"], 60000)
        self.assertEqual(snapshot["budget"]["min_chars"], 40000)

        snapshot = resolve_writing_policy(
            profile="academic_paper",
            manifest_overrides={"extra_forbidden_terms": ["测试词"]},
        )
        self.assertIn("测试词", snapshot["extra_forbidden_terms"])
        self.assertTrue(snapshot["_meta"]["sources"]["report_manifest_config"])

    def test_locked_fields_cannot_be_overridden(self) -> None:
        base = load_writing_policy()
        for locked in base["locked"]["fields"]:
            with self.assertRaises(PolicyError):
                resolve_writing_policy(
                    profile="academic_paper",
                    manifest_overrides={locked: "changed"},
                )

    def test_unknown_or_invalid_override_rejected(self) -> None:
        with self.assertRaises(PolicyError):
            resolve_writing_policy(
                profile="academic_paper",
                manifest_overrides={"not_a_field": True},
            )
        with self.assertRaises(PolicyError):
            resolve_writing_policy(
                profile="academic_paper",
                manifest_overrides={"budget": {"max_chars": -1}},
            )

    def test_array_merge_append_and_replace(self) -> None:
        merged = resolve_writing_policy(
            profile="academic_paper",
            manifest_overrides={"allowed_sections": ["新章节"]},
        )
        self.assertIn("新章节", merged["allowed_sections"])
        self.assertIn("摘要", merged["allowed_sections"])

    def test_compression_review_options_replace(self) -> None:
        merged = resolve_writing_policy(
            profile="academic_paper",
            manifest_overrides={
                "compression_review_options": {"limit_echo_terms": ["仅此一句"]}
            },
        )
        options = merged["compression_review_options"]
        self.assertIn("limit_echo_terms", options)
        self.assertEqual(options["limit_echo_terms"], ["仅此一句"])

    def test_submission_policy_layer_and_profile_validation(self) -> None:
        with self.assertRaises(PolicyError):
            resolve_submission_policy(deliverable_layer="D")
        with self.assertRaises(PolicyError):
            resolve_submission_policy(artifact_profile="not_a_profile")
        with self.assertRaises(PolicyError):
            resolve_submission_policy(deliverable_layer="A", artifact_profile="method_appendix")
        resolved = resolve_submission_policy(deliverable_layer="B")
        self.assertEqual(resolved["profile"], "method_appendix")
        self.assertEqual(resolved["deliverable_layer"], "B")

    def test_old_snapshot_accepted_when_version_and_id_match(self) -> None:
        snapshot = resolve_writing_policy(profile="academic_paper")
        snapshot["policy_version"] = "0.9.0"
        resolved = resolve_submission_policy(
            deliverable_layer="A",
            artifact_profile="academic_paper",
            writing_policy_id="default-writing-policy",
            writing_policy_version="0.9.0",
            writing_policy_snapshot=snapshot,
        )
        self.assertEqual(resolved["policy_version"], "0.9.0")
        self.assertEqual(resolved["snapshot"]["policy_version"], "0.9.0")

    def test_snapshot_mismatch_rejected(self) -> None:
        snapshot = resolve_writing_policy(profile="academic_paper")
        with self.assertRaises(PolicyError):
            resolve_submission_policy(
                deliverable_layer="A",
                artifact_profile="academic_paper",
                writing_policy_id="other-policy",
                writing_policy_snapshot=snapshot,
            )
        with self.assertRaises(PolicyError):
            resolve_submission_policy(
                deliverable_layer="A",
                artifact_profile="academic_paper",
                writing_policy_version="9.9.9",
                writing_policy_snapshot=snapshot,
            )

    def test_unknown_policy_id_rejected(self) -> None:
        with self.assertRaises(PolicyError):
            resolve_submission_policy(writing_policy_id="unknown-policy")

    def test_constants_are_stable(self) -> None:
        self.assertEqual(SUPPORTED_LAYERS, ("A", "B", "C"))
        self.assertEqual(
            KNOWN_PROFILES,
            ("academic_paper", "method_appendix", "technical_report", "research_memo"),
        )
        self.assertEqual(
            COMPRESSION_REVIEW_STATUSES,
            ("not_required", "pending", "passed", "returned"),
        )

    def test_audit_summary_validation(self) -> None:
        clean = validate_writing_audit_summary(
            {"errors": 0, "warnings": 2, "review_items": 1, "approval_blockers": 0}
        )
        self.assertEqual(clean["warnings"], 2)
        with self.assertRaises(PolicyError):
            validate_writing_audit_summary({"errors": -1})
        with self.assertRaises(PolicyError):
            validate_writing_audit_summary({"errors": "many"})
        with self.assertRaises(PolicyError):
            validate_writing_audit_summary({"unknown": 1})
        with self.assertRaises(PolicyError):
            validate_writing_audit_summary([])

    def test_policy_json_serializable(self) -> None:
        json.dumps(load_writing_policy(), ensure_ascii=False)


if __name__ == "__main__":
    unittest.main()
