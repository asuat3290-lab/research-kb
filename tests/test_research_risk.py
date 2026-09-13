from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import jsonschema

from research_kb.research_risk import (
    POLICY_VERSION,
    SCHEMA_VERSION,
    audit_research_risk,
    main,
    render_markdown,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "research_risk"
SCHEMA_FILE = REPO_ROOT / "src" / "research_kb" / "research_risk.schema.json"
POLICY_DOC = REPO_ROOT / "docs" / "research-risk-policy.md"

FORBIDDEN_PROJECT_TERMS = tuple("?" * length for length in (3, 4, 2, 3, 4))


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def load_tri_case(name: str) -> tuple[dict, dict, dict]:
    case_dir = FIXTURE_DIR / "tri_file" / name
    return tuple(
        json.loads((case_dir / filename).read_text(encoding="utf-8"))
        for filename in ("design.json", "results.json", "adjudication.json")
    )


def rule_ids(result, bucket=None):
    return {
        finding.rule_id
        for finding in result.findings
        if bucket is None or finding.bucket == bucket
    }


def canonical_design_hash(doc: dict) -> str:
    payload = json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
    payload = payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(payload).hexdigest()


class SchemaTests(unittest.TestCase):
    def test_schema_is_valid_draft_2020_12(self) -> None:
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["properties"]["schema_version"]["const"], SCHEMA_VERSION)

    def test_fixtures_validate_against_schema(self) -> None:
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        for fixture in sorted(FIXTURE_DIR.glob("*.json")):
            with self.subTest(fixture=fixture.name):
                doc = json.loads(fixture.read_text(encoding="utf-8"))
                jsonschema.validate(doc, schema)

    def test_tri_file_sidecars_validate_against_schema(self) -> None:
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        results_schema = {
            "$ref": "#/$defs/research_results",
            "$defs": schema["$defs"],
        }
        adjudication_schema = {
            "$ref": "#/$defs/research_adjudication",
            "$defs": schema["$defs"],
        }
        for case in sorted((FIXTURE_DIR / "tri_file").iterdir()):
            if not case.is_dir():
                continue
            with self.subTest(case=case.name):
                design, results, adjudication = load_tri_case(case.name)
                jsonschema.validate(design, schema)
                jsonschema.validate(results, results_schema)
                jsonschema.validate(adjudication, adjudication_schema)

    def test_schema_rejects_invalid_level(self) -> None:
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        doc = load_fixture("disabled.json")
        doc["policy_level"] = "extreme"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(doc, schema)
        result = audit_research_risk(doc)
        self.assertIn("SCHEMA_INVALID", rule_ids(result, "errors"))

    def test_system_files_are_project_agnostic(self) -> None:
        paths = [
            SCHEMA_FILE,
            REPO_ROOT / "src" / "research_kb" / "research_risk.py",
            POLICY_DOC,
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for term in FORBIDDEN_PROJECT_TERMS:
                self.assertNotIn(term, text, f"{term} found in {path.name}")

    def test_policy_doc_versions_match_code(self) -> None:
        text = POLICY_DOC.read_text(encoding="utf-8")
        self.assertIn(f"policy_version: {POLICY_VERSION}", text)
        self.assertIn(f"schema_version: {SCHEMA_VERSION}", text)


class FixtureRuleTests(unittest.TestCase):
    def test_valid_genealogical_has_no_findings(self) -> None:
        result = audit_research_risk(load_fixture("valid-genealogical.json"))
        self.assertEqual(
            result.as_dict()["summary"],
            {"errors": 0, "warnings": 0, "review_items": 0, "approval_blockers": 0},
        )

    def test_pseudo_rival_reported(self) -> None:
        result = audit_research_risk(load_fixture("pseudo-rival.json"))
        self.assertIn("RIVAL_HYPOTHESIS_NOT_DISCRIMINATING", rule_ids(result, "warnings"))

    def test_never_fail_reported(self) -> None:
        result = audit_research_risk(load_fixture("never-fail.json"))
        self.assertIn("ALL_OUTCOMES_PRESERVE_PRIMARY_HYPOTHESIS", rule_ids(result, "errors"))
        self.assertIn(
            "ALL_OUTCOMES_PRESERVE_PRIMARY_HYPOTHESIS", rule_ids(result, "approval_blockers")
        )

    def test_holdout_contamination_reported(self) -> None:
        result = audit_research_risk(load_fixture("holdout-contaminated.json"))
        self.assertIn("HOLDOUT_CONTAMINATED", rule_ids(result, "errors"))
        self.assertIn("HOLDOUT_CONTAMINATED", rule_ids(result, "approval_blockers"))

    def test_design_drift_reported(self) -> None:
        result = audit_research_risk(load_fixture("design-drift.json"))
        self.assertIn("DESIGN_DRIFT_UNDISCLOSED", rule_ids(result, "errors"))
        self.assertIn("DESIGN_DRIFT_UNDISCLOSED", rule_ids(result, "approval_blockers"))

    def test_negative_control_failure_reported(self) -> None:
        result = audit_research_risk(load_fixture("negative-control-fails.json"))
        self.assertIn("NEGATIVE_CONTROL_PASSES_PRIMARY_CRITERIA", rule_ids(result, "errors"))

    def test_contribution_mismatch_reported(self) -> None:
        result = audit_research_risk(load_fixture("contribution-mismatch.json"))
        self.assertIn("CONTRIBUTION_TYPE_MISMATCH", rule_ids(result, "errors"))

    def test_disabled_has_no_findings(self) -> None:
        result = audit_research_risk(load_fixture("disabled.json"))
        self.assertEqual(
            result.as_dict()["summary"],
            {"errors": 0, "warnings": 0, "review_items": 0, "approval_blockers": 0},
        )

    def test_risk_bearing_missing_reported(self) -> None:
        result = audit_research_risk(load_fixture("risk-bearing-missing.json"))
        self.assertIn("RISK_BEARING_MISSING", rule_ids(result, "errors"))
        self.assertIn("RISK_BEARING_MISSING", rule_ids(result, "approval_blockers"))

    def test_bridge_aggregated_reported(self) -> None:
        result = audit_research_risk(load_fixture("bridge-aggregated.json"))
        self.assertIn("BRIDGE_STRENGTH_AGGREGATED", rule_ids(result, "warnings"))

    def test_no_open_falsification_reported(self) -> None:
        result = audit_research_risk(load_fixture("no-open-falsification.json"))
        self.assertIn("NO_OPEN_FALSIFICATION_CONDITION", rule_ids(result, "errors"))
        self.assertIn(
            "NO_OPEN_FALSIFICATION_CONDITION", rule_ids(result, "approval_blockers")
        )

    def test_chronology_only_reported(self) -> None:
        result = audit_research_risk(load_fixture("chronology-only.json"))
        self.assertIn("CHRONOLOGY_USED_AS_CONNECTION_EVIDENCE", rule_ids(result, "errors"))
        self.assertIn(
            "CHRONOLOGY_USED_AS_CONNECTION_EVIDENCE",
            rule_ids(result, "approval_blockers"),
        )

    def test_contribution_exceeds_bridge_reported(self) -> None:
        result = audit_research_risk(load_fixture("contribution-exceeds-bridge.json"))
        self.assertIn("CONTRIBUTION_EXCEEDS_BRIDGE_STATUS", rule_ids(result, "errors"))

    def test_control_overgeneralized_reported(self) -> None:
        result = audit_research_risk(load_fixture("control-overgeneralized.json"))
        self.assertIn("NEGATIVE_CONTROL_OVERGENERALIZED", rule_ids(result, "errors"))

    def test_design_result_mixed_reported(self) -> None:
        result = audit_research_risk(load_fixture("design-result-mixed.json"))
        self.assertIn("DESIGN_RESULT_MIXED", rule_ids(result, "errors"))

    def test_evidence_role_stale_reported(self) -> None:
        result = audit_research_risk(load_fixture("evidence-role-stale.json"))
        self.assertIn("EVIDENCE_ROLE_STALE", rule_ids(result, "errors"))


class BehavioralTests(unittest.TestCase):
    def test_disabled_via_wrapper(self) -> None:
        doc = load_fixture("disabled.json")
        doc["research_risk_policy"] = {"enabled": False, "level": "none"}
        result = audit_research_risk(doc)
        self.assertEqual(result.as_dict()["enabled"], False)
        self.assertEqual(
            result.as_dict()["summary"],
            {"errors": 0, "warnings": 0, "review_items": 0, "approval_blockers": 0},
        )

    def test_wrapper_takes_precedence(self) -> None:
        doc = load_fixture("valid-genealogical.json")
        doc["enabled"] = False
        doc["research_risk_policy"] = {"enabled": True, "level": "interpretive"}
        result = audit_research_risk(doc)
        self.assertEqual(result.as_dict()["enabled"], True)
        self.assertEqual(result.as_dict()["policy_level"], "interpretive")
        self.assertEqual(result.as_dict()["summary"]["errors"], 0)

    def test_holdout_sources_legacy_field_is_clean(self) -> None:
        doc = load_fixture("valid-genealogical.json")
        doc["materials"] = [
            {
                "id": "M1",
                "source_ref": "early-works",
                "evidence_role": "validation",
                "seen_before_lock": True,
            }
        ]
        doc["holdout_sources"] = [
            {"id": "H1", "source_ref": "unseen-letter", "seen_before_lock": False}
        ]
        result = audit_research_risk(doc)
        self.assertNotIn("HOLDOUT_CONTAMINATED", rule_ids(result))
        self.assertNotIn("VALIDATION_OR_HOLDOUT_MISSING", rule_ids(result))

    def test_holdout_sources_contamination_detected(self) -> None:
        doc = load_fixture("valid-genealogical.json")
        doc["materials"] = [
            {
                "id": "M1",
                "source_ref": "early-works",
                "evidence_role": "validation",
                "seen_before_lock": True,
            }
        ]
        doc["holdout_sources"] = [
            {"id": "H1", "source_ref": "unseen-letter", "seen_before_lock": True}
        ]
        result = audit_research_risk(doc)
        self.assertIn("HOLDOUT_CONTAMINATED", rule_ids(result, "errors"))
        self.assertIn("HOLDOUT_CONTAMINATED", rule_ids(result, "approval_blockers"))

    def test_locked_design_blocks_incomplete_work(self) -> None:
        doc = load_fixture("valid-genealogical.json")
        doc["design_status"] = "locked"
        doc["locked_at"] = "2026-08-07T00:00:00+08:00"
        for control in doc["negative_controls"]:
            control["actual_result"] = None
        doc["adversarial_review"]["status"] = "pending"
        doc["validation_status"]["required"] = True
        doc["validation_status"]["completed"] = False
        result = audit_research_risk(doc)
        blockers = rule_ids(result, "approval_blockers")
        self.assertIn("ADVERSARIAL_REVIEW_INCOMPLETE", blockers)
        self.assertIn("VALIDATION_INCOMPLETE", blockers)
        self.assertIn("NEGATIVE_CONTROL_NOT_COMPLETED", blockers)

    def test_locked_requires_locked_at(self) -> None:
        doc = load_fixture("design-drift.json")
        del doc["locked_at"]
        result = audit_research_risk(doc)
        self.assertIn("LOCKED_AT_MISSING", rule_ids(result, "errors"))

    def test_input_sha256_uses_raw_bytes(self) -> None:
        doc = load_fixture("valid-genealogical.json")
        raw = json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
        result = audit_research_risk(doc)
        self.assertEqual(result.input_sha256, hashlib.sha256(raw).hexdigest())

        raw2 = b'{"x": 1}'
        result2 = audit_research_risk(json.loads(raw2), input_bytes=raw2)
        self.assertEqual(result2.input_sha256, hashlib.sha256(raw2).hexdigest())

    def test_markdown_includes_findings(self) -> None:
        result = audit_research_risk(load_fixture("never-fail.json"))
        text = render_markdown(result.as_dict())
        self.assertIn("ALL_OUTCOMES_PRESERVE_PRIMARY_HYPOTHESIS", text)
        self.assertIn(f"policy_version: {POLICY_VERSION}", text)

    def test_tri_file_valid_has_no_findings_and_hash_matched(self) -> None:
        design, results, adjudication = load_tri_case("valid")
        result = audit_research_risk(
            design, results_doc=results, adjudication_doc=adjudication
        )
        self.assertEqual(
            result.as_dict()["summary"],
            {"errors": 0, "warnings": 0, "review_items": 0, "approval_blockers": 0},
        )
        self.assertEqual(result.design_hash_status, "matched")

    def test_post_lock_validation_missing_reported(self) -> None:
        design, results, adjudication = load_tri_case("post-lock-missing")
        result = audit_research_risk(
            design, results_doc=results, adjudication_doc=adjudication
        )
        self.assertIn("POST_LOCK_VALIDATION_MISSING", rule_ids(result, "errors"))
        self.assertIn(
            "POST_LOCK_VALIDATION_MISSING", rule_ids(result, "approval_blockers")
        )

    def test_validation_contaminated_reported(self) -> None:
        design, results, adjudication = load_tri_case("validation-contaminated")
        result = audit_research_risk(
            design, results_doc=results, adjudication_doc=adjudication
        )
        self.assertIn("VALIDATION_EVIDENCE_CONTAMINATED", rule_ids(result, "errors"))
        self.assertIn(
            "VALIDATION_EVIDENCE_CONTAMINATED", rule_ids(result, "approval_blockers")
        )

    def test_hash_mismatch_reported(self) -> None:
        design, results, adjudication = load_tri_case("hash-mismatch")
        result = audit_research_risk(
            design, results_doc=results, adjudication_doc=adjudication
        )
        self.assertIn("LOCKED_DESIGN_HASH_MISMATCH", rule_ids(result, "errors"))
        self.assertIn(
            "LOCKED_DESIGN_HASH_MISMATCH", rule_ids(result, "approval_blockers")
        )
        self.assertEqual(result.design_hash_status, "mismatch")

    def test_supported_without_pde_reported(self) -> None:
        design, _, _ = load_tri_case("rival-failure-only")
        results = {
            "schema_version": SCHEMA_VERSION,
            "design_version": 1,
            "design_sha256": canonical_design_hash(design),
            "hypothesis_statuses": [
                {"hypothesis_id": "H1", "status": "supported"},
                {"hypothesis_id": "H2", "status": "falsified"},
                {"hypothesis_id": "H3", "status": "falsified"},
            ],
            "positive_discriminating_evidence": [],
            "observations": [],
        }
        adjudication = {
            "schema_version": SCHEMA_VERSION,
            "design_version": 1,
            "design_sha256": canonical_design_hash(design),
            "adjudication_version": 1,
            "verdicts": [
                {
                    "hypothesis_id": "H1",
                    "status": "supported",
                    "reasoning": "rival failure only",
                }
            ],
        }
        result = audit_research_risk(
            design, results_doc=results, adjudication_doc=adjudication
        )
        self.assertIn(
            "PRIMARY_SUPPORTED_BY_RIVAL_FAILURE_ONLY", rule_ids(result, "errors")
        )
        self.assertIn(
            "PRIMARY_SUPPORTED_BY_RIVAL_FAILURE_ONLY",
            rule_ids(result, "approval_blockers"),
        )

    def test_pde_with_false_contract_field_does_not_count(self) -> None:
        design = load_fixture("valid-genealogical.json")
        design["design_status"] = "locked"
        design["locked_at"] = "2026-08-07T00:00:00+08:00"
        design["validation_status"] = {"required": False, "completed": False}
        results = {
            "schema_version": SCHEMA_VERSION,
            "design_version": 1,
            "design_sha256": canonical_design_hash(design),
            "hypothesis_statuses": [
                {"hypothesis_id": "H1", "status": "supported"},
            ],
            "positive_discriminating_evidence": [
                {
                    "id": "P1",
                    "evidence_class": "source_texts",
                    "observed_after_lock": False,
                    "outcome_unknown_at_lock": True,
                    "supports_primary_prediction": True,
                    "discriminates_against": ["H2"],
                }
            ],
            "observations": [],
        }
        adjudication = {
            "schema_version": SCHEMA_VERSION,
            "design_version": 1,
            "design_sha256": canonical_design_hash(design),
            "adjudication_version": 1,
            "verdicts": [
                {
                    "hypothesis_id": "H1",
                    "status": "supported",
                    "reasoning": "no discriminating rival",
                }
            ],
        }
        result = audit_research_risk(
            design, results_doc=results, adjudication_doc=adjudication
        )
        self.assertIn(
            "PRIMARY_SUPPORTED_BY_RIVAL_FAILURE_ONLY", rule_ids(result, "errors")
        )


class CliTests(unittest.TestCase):
    def test_cli_prints_json_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            source = tmp / "research-risk.json"
            source.write_bytes(
                json.dumps(load_fixture("valid-genealogical.json"), ensure_ascii=False).encode("utf-8")
            )
            manifest = tmp / "audit.json"
            markdown = tmp / "audit.md"
            code = main([str(source), "--manifest", str(manifest), "--markdown", str(markdown)])
            self.assertEqual(code, 0)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["errors"], 0)
            self.assertTrue(markdown.exists())

    def test_cli_strict_fails_on_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            source = tmp / "research-risk.json"
            source.write_bytes(
                json.dumps(load_fixture("never-fail.json"), ensure_ascii=False).encode("utf-8")
            )
            code = main([str(source), "--strict"])
            self.assertEqual(code, 1)

    def test_cli_tri_file_writes_manifest(self) -> None:
        design, results, adjudication = load_tri_case("valid")
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            design_path = tmp / "research-risk-design.json"
            results_path = tmp / "research-risk-results.json"
            adjudication_path = tmp / "research-risk-adjudication.json"
            design_path.write_text(json.dumps(design, ensure_ascii=False), encoding="utf-8")
            results_path.write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
            adjudication_path.write_text(
                json.dumps(adjudication, ensure_ascii=False), encoding="utf-8"
            )
            manifest = tmp / "audit.json"
            code = main(
                [
                    str(design_path),
                    "--results",
                    str(results_path),
                    "--adjudication",
                    str(adjudication_path),
                    "--manifest",
                    str(manifest),
                    "--strict",
                ]
            )
            self.assertEqual(code, 0)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["errors"], 0)
            self.assertEqual(data["design_hash_status"], "matched")


if __name__ == "__main__":
    unittest.main()

