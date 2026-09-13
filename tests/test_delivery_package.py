from __future__ import annotations

import io
import re
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from research_kb.delivery_package import (
    MANIFEST_SPEC_ANCHORS,
    compute_sha256,
    main as package_main,
    upgrade_manifest,
    validate_delivery_manifest,
)
from research_kb.writing_audit import audit_document

REPO_ROOT = Path(__file__).resolve().parents[1]

PROFILES = ("academic_paper", "method_appendix", "technical_report")
LAYERS = ("A", "B", "C")
MARKDOWN = {
    "academic_paper": "# \u6458\u8981\n\n\u6458\u8981\u6b63\u6587\u3002\n\n# \u5bfc\u8bba\n\n\u5bfc\u8bba\u6b63\u6587\u3002\n\n" + "\u8bba\u8bc1\u8865\u5145\u5185\u5bb9\u3002" * 6000 + "\n\n# \u7ed3\u8bba\n\n\u7ed3\u8bba\u6b63\u6587\u3002\n\n# \u53c2\u8003\u6587\u732e\n\n\u53c2\u8003\u6587\u732e\u3002\n",
    "method_appendix": "# \u8bc1\u636e\u7b49\u7ea7\n\n\u8bc1\u636e\u7b49\u7ea7\u8bf4\u660e\u3002\n\n# \u5b9a\u4e49\u53e5\u4e0e\u529f\u80fd\u53e5\n\n\u5b9a\u4e49\u53e5\u4e0e\u529f\u80fd\u53e5\u8bf4\u660e\u3002\n",
    "technical_report": "# \u6280\u672f\u62a5\u544a\n\n\u7cfb\u7edf\u72b6\u6001\u3002\n",
}


def _audit_result(profile: str, source_name: str) -> dict:
    snapshot = audit_document(MARKDOWN[profile], profile=profile).policy_snapshot
    result = audit_document(
        MARKDOWN[profile],
        profile=profile,
        source_path=source_name,
        policy_snapshot=snapshot,
    )
    return result.as_dict()


class ManifestAnchorTests(unittest.TestCase):
    def test_manifest_anchors_exist_and_are_unique(self) -> None:
        doc = (REPO_ROOT / "docs" / "manifest-format.md").read_text(encoding="utf-8")
        anchors = re.findall(r'<a id="([^"]+)"></a>', doc)
        self.assertEqual(len(anchors), len(set(anchors)), "duplicate manifest anchors")
        missing = sorted(set(MANIFEST_SPEC_ANCHORS) - set(anchors))
        self.assertEqual(missing, [])
        unregistered = sorted(set(anchors) - set(MANIFEST_SPEC_ANCHORS))
        self.assertEqual(unregistered, [])

    def test_manifest_anchor_files_exist(self) -> None:
        for anchor, rel in MANIFEST_SPEC_ANCHORS.items():
            path = REPO_ROOT / rel
            self.assertTrue(path.is_file(), f"{anchor} -> {rel}")

    def test_manifest_anchor_references_stay_registered(self) -> None:
        docs = (REPO_ROOT / "docs" / "manifest-format.md").read_text(encoding="utf-8")
        body = "\n".join(
            p.read_text(encoding="utf-8")
            for p in (REPO_ROOT / "src" / "research_kb").glob("*.py")
        )
        tests = (REPO_ROOT / "tests" / "test_delivery_package.py").read_text(encoding="utf-8")
        for anchor in MANIFEST_SPEC_ANCHORS:
            self.assertIn(anchor, docs)
        for needle in re.findall(r"manifest-[a-z0-9]+-[a-z0-9_-]+", body + "\n" + tests):
            self.assertIn(needle, MANIFEST_SPEC_ANCHORS, f"unregistered manifest anchor {needle!r}")


class DeliveryPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.audits: dict[str, dict] = {}
        for profile, layer in zip(PROFILES, LAYERS):
            name = f"{layer}-artifact.md"
            (self.root / name).write_text(MARKDOWN[profile], encoding="utf-8")
            audit = _audit_result(profile, name)
            audit_path = self.root / f"audit-{layer}.json"
            audit_path.write_text(json.dumps(audit, ensure_ascii=False), encoding="utf-8")
            self.audits[layer] = audit

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _manifest(self) -> dict:
        artifacts = []
        supporting_artifacts = []
        for profile, layer in zip(PROFILES, LAYERS):
            name = f"{layer}-artifact.md"
            audit_name = f"audit-{layer}.json"
            artifacts.append(
                {
                    "file": name,
                    "deliverable_layer": layer,
                    "artifact_profile": profile,
                    "audit_report": audit_name,
                    "sha256": compute_sha256(self.root / name),
                    "audit_sha256": compute_sha256(self.root / audit_name),
                }
            )
            supporting_artifacts.append(
                {
                    "file": audit_name,
                    "type": "audit_json",
                    "sha256": compute_sha256(self.root / audit_name),
                }
            )
        summary = {
            "errors": len(self.audits["A"]["errors"]),
            "warnings": len(self.audits["A"]["warnings"]),
            "review_items": len(self.audits["A"]["review_items"]),
            "approval_blockers": len(self.audits["A"]["approval_blockers"]),
        }
        manifest = {
            "manifest_version": "2.0",
            "delivery_package_id": "v6.4.1-test-package",
            "policy_id": "default-writing-policy",
            "policy_version": "1.2.0",
            "created_at": "2026-08-06T21:30:00+08:00",
            "policy_fingerprint": self.audits["A"]["policy_fingerprint"],
            "package_state": "REVIEW",
            "artifact_audit": summary,
            "research_approval": {"review_items": 0, "approval_blockers": 0},
            "final_approval": "pending",
            "supporting_artifacts": supporting_artifacts,
            "policy_snapshot_sha256": self.audits["A"]["policy_fingerprint"],
            "artifacts": artifacts,
        }
        manifest["package_sha256"] = compute_sha256(self.root / "audit-A.json")
        return manifest

    def test_valid_package_passes(self) -> None:
        manifest = self._manifest()
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertTrue(result["valid"], result["problems"])
        self.assertEqual(result["problems"], [])
        self.assertEqual(len(result["artifacts"]), 3)
        self.assertTrue(all(item["valid"] for item in result["artifacts"]))

    def test_bad_artifact_hash_detected(self) -> None:
        manifest = self._manifest()
        manifest["artifacts"][0]["sha256"] = "sha256:" + "0" * 64
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertFalse(result["valid"])
        self.assertFalse(result["artifacts"][0]["valid"])
        self.assertTrue(any("sha256 mismatch" in problem for problem in result["problems"]))

    def test_bad_audit_hash_detected(self) -> None:
        manifest = self._manifest()
        manifest["artifacts"][1]["audit_sha256"] = "sha256:" + "1" * 64
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(any("audit sha256 mismatch" in problem for problem in result["problems"]))

    def test_layer_profile_mismatch_rejected(self) -> None:
        manifest = self._manifest()
        manifest["artifacts"][0]["artifact_profile"] = "method_appendix"
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(any("does not match layer" in problem for problem in result["problems"]))

    def test_missing_artifact_file_detected(self) -> None:
        manifest = self._manifest()
        manifest["artifacts"][2]["file"] = "missing.md"
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(any("artifact file is missing" in problem for problem in result["problems"]))

    def test_audit_summary_mismatch_detected(self) -> None:
        manifest = self._manifest()
        manifest["artifact_audit"] = {"errors": 0, "warnings": 0, "review_items": 0, "approval_blockers": 1}
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(any("artifact_audit" in problem for problem in result["problems"]))

    def test_legacy_manifest_is_readable(self) -> None:
        manifest = self._manifest()
        for key in (
            "manifest_version",
            "package_state",
            "artifact_audit",
            "writing_policy_audit",
            "created_at",
            "research_approval",
            "final_approval",
            "supporting_artifacts",
            "policy_snapshot_sha256",
        ):
            manifest.pop(key, None)
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertTrue(result["valid"], result["problems"])
        self.assertTrue(result["legacy"])
        self.assertTrue(result["migration_recommended"])

    def test_upgrade_manifest_is_non_mutating(self) -> None:
        manifest = self._manifest()
        for key in (
            "manifest_version",
            "package_state",
            "artifact_audit",
            "writing_policy_audit",
            "created_at",
            "research_approval",
            "final_approval",
            "supporting_artifacts",
            "policy_snapshot_sha256",
        ):
            manifest.pop(key, None)
        before = json.dumps(manifest, ensure_ascii=False, sort_keys=True)
        upgraded = upgrade_manifest(manifest)
        self.assertEqual(json.dumps(manifest, ensure_ascii=False, sort_keys=True), before)
        self.assertEqual(upgraded["manifest_version"], "2.0")
        self.assertEqual(upgraded["package_state"], "REVIEW")
        self.assertEqual(upgraded["artifact_audit"]["errors"], 0)
        self.assertEqual(upgraded["writing_policy_audit"]["errors"], 0)
        self.assertEqual(upgraded["created_at"], "")
        self.assertEqual(upgraded["final_approval"], "pending")
        self.assertEqual(upgraded["supporting_artifacts"], [])

    def test_supporting_artifact_hash_mismatch(self) -> None:
        manifest = self._manifest()
        manifest["supporting_artifacts"][0]["sha256"] = "sha256:" + "4" * 64
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any(
                "supporting artifact sha256 mismatch" in problem
                for problem in result["problems"]
            )
        )

    def test_v2_requires_created_at(self) -> None:
        manifest = self._manifest()
        manifest.pop("created_at", None)
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(any("created_at" in problem for problem in result["problems"]))

    def test_artifact_audit_preferred_over_writing_policy_audit(self) -> None:
        manifest = self._manifest()
        manifest["writing_policy_audit"] = {
            "errors": 99,
            "warnings": 99,
            "review_items": 99,
            "approval_blockers": 99,
        }
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertTrue(result["valid"], result["problems"])

    def test_audit_fingerprint_mismatch_detected(self) -> None:
        manifest = self._manifest()
        audit_name = "audit-A.json"
        audit_path = self.root / audit_name
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        audit["policy_fingerprint"] = "sha256:" + "2" * 64
        audit_path.write_text(json.dumps(audit, ensure_ascii=False), encoding="utf-8")
        manifest["artifacts"][0]["audit_sha256"] = compute_sha256(audit_path)
        result = validate_delivery_manifest(manifest, base_dir=self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(any("policy_fingerprint" in problem for problem in result["problems"]))

    def test_cli_exit_codes(self) -> None:
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(self._manifest(), ensure_ascii=False), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(package_main([str(manifest_path)]), 0)
        bad = self._manifest()
        bad["artifacts"][0]["sha256"] = "sha256:" + "3" * 64
        manifest_path.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(package_main([str(manifest_path)]), 1)


if __name__ == "__main__":
    unittest.main()
