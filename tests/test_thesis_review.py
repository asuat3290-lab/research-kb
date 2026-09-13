from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import jsonschema

from research_kb.thesis_review import (
    POLICY_VERSION,
    SCHEMA_VERSION,
    audit_review_dir,
    main,
    scaffold_review_dir,
    validate_argument_map,
    validate_review_summary,
    validate_revision_registry,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "thesis_review"
SCHEMA_FILE = REPO_ROOT / "src" / "research_kb" / "thesis_review.schema.json"
POLICY_DOC = REPO_ROOT / "docs" / "thesis-review-policy.md"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


class SchemaTests(unittest.TestCase):
    def test_schema_is_valid_draft_2020_12(self) -> None:
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["properties"]["schema_version"]["const"], SCHEMA_VERSION)

    _DEF_BY_FILE = {
        "summary.json": "review_summary",
        "argument-map.json": "argument_map",
        "revision-registry.json": "revision_registry",
    }

    def _subschema(self, name: str) -> dict:
        suffix = name.split("-", 1)[1]
        return {"$ref": f"#/$defs/{self._DEF_BY_FILE[suffix]}"}

    def test_fixtures_validate_against_schema(self) -> None:
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        for name in ("valid-summary.json", "valid-argument-map.json", "valid-revision-registry.json"):
            with self.subTest(fixture=name):
                validator.evolve(schema=self._subschema(name)).validate(load_fixture(name))

    def test_invalid_fixtures_fail_schema(self) -> None:
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        for name in ("invalid-summary.json", "invalid-argument-map.json", "invalid-revision-registry.json"):
            with self.subTest(fixture=name):
                with self.assertRaises(jsonschema.ValidationError):
                    validator.evolve(schema=self._subschema(name)).validate(load_fixture(name))


class ValidatorTests(unittest.TestCase):
    def test_valid_summary_passes(self) -> None:
        self.assertEqual(validate_review_summary(load_fixture("valid-summary.json")), [])

    def test_invalid_summary_reports_problems(self) -> None:
        problems = validate_review_summary(load_fixture("invalid-summary.json"))
        paths = {path for path, _ in problems}
        self.assertIn("paper_id", paths)
        self.assertIn("stage", paths)
        self.assertIn("$.findings[0].severity", paths)

    def test_valid_argument_map_passes(self) -> None:
        self.assertEqual(validate_argument_map(load_fixture("valid-argument-map.json")), [])

    def test_invalid_argument_map_reports_unknown_dependency(self) -> None:
        problems = validate_argument_map(load_fixture("invalid-argument-map.json"))
        self.assertTrue(any("unknown node id" in message for _, message in problems))

    def test_valid_revision_registry_passes(self) -> None:
        self.assertEqual(validate_revision_registry(load_fixture("valid-revision-registry.json")), [])

    def test_invalid_revision_registry_reports_problems(self) -> None:
        problems = validate_revision_registry(load_fixture("invalid-revision-registry.json"))
        paths = {path for path, _ in problems}
        self.assertIn("$.items[0].problem_type", paths)
        self.assertIn("$.items[0].problem_description", paths)
        self.assertIn("$.items[0].human_status", paths)

    def test_duplicate_ids_reported(self) -> None:
        doc = load_fixture("valid-summary.json")
        doc["findings"].append(dict(doc["findings"][0]))
        problems = validate_review_summary(doc)
        self.assertTrue(any("duplicate id" in message for _, message in problems))


class AuditDirTests(unittest.TestCase):
    _FIXTURE_BY_ARTIFACT = {
        "00-review-summary.json": "valid-summary.json",
        "01-argument-map.json": "valid-argument-map.json",
        "08-revision-items.json": "valid-revision-registry.json",
    }

    def _make_review_dir(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="thesis-review-test-"))
        scaffold_review_dir(directory)
        for name, fixture in self._FIXTURE_BY_ARTIFACT.items():
            (directory / name).write_text(
                json.dumps(load_fixture(fixture), ensure_ascii=False),
                encoding="utf-8",
            )
        return directory

    def test_scaffold_creates_required_files(self) -> None:
        directory = self._make_review_dir()
        from research_kb.thesis_review import REQUIRED_REVIEW_MARKDOWN

        for name in REQUIRED_REVIEW_MARKDOWN:
            self.assertTrue((directory / name).is_file(), name)

    def test_audit_review_dir_ok_on_valid_dir(self) -> None:
        directory = self._make_review_dir()
        result = audit_review_dir(directory)
        self.assertEqual(result.errors, 0)
        self.assertTrue(result.ok)

    def test_audit_review_dir_reports_missing_files(self) -> None:
        directory = self._make_review_dir()
        (directory / "00-review-summary.md").unlink()
        result = audit_review_dir(directory)
        self.assertGreater(result.errors, 0)
        self.assertIn("00-review-summary.md", result.missing_files)


class CliTests(unittest.TestCase):
    def test_main_init_and_validate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="thesis-review-cli-") as tmp:
            directory = Path(tmp) / "review"
            self.assertEqual(main(["init", str(directory)]), 0)
            self.assertTrue((directory / "00-review-summary.md").is_file())
            self.assertEqual(main(["validate", str(directory)]), 0)


class PolicyDocTests(unittest.TestCase):
    def test_policy_doc_versions_match_module(self) -> None:
        text = POLICY_DOC.read_text(encoding="utf-8")
        self.assertIn(f"policy_version: {POLICY_VERSION}", text)
        self.assertIn(f"schema_version: {SCHEMA_VERSION}", text)


if __name__ == "__main__":
    unittest.main()
