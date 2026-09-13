from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
import tomllib
import unittest
from contextlib import closing
from pathlib import Path

from research_kb import __version__
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository
from research_kb.max_research.persistence.migrations import (
    _backfill_schema_v2,
    _backfill_schema_v4,
    _backfill_schema_v8,
    _statements,
    migration_files,
    validate_migration_release,
    validate_schema_ledger,
)
from research_kb.max_research.persistence.schema_manifest import verify_schema_manifest
from research_kb.research_risk import load_research_risk_schema
from research_kb.thesis_review import load_review_schema, scaffold_review_dir
from research_kb.writing_policy import load_policy_schema, load_writing_policy


class QV1CResourceTests(unittest.TestCase):
    def test_installed_safe_json_loaders_and_nonempty_scaffold(self) -> None:
        self.assertIsInstance(load_research_risk_schema(), dict)
        self.assertIsInstance(load_writing_policy(), dict)
        self.assertIsInstance(load_policy_schema(), dict)
        self.assertIsInstance(load_review_schema(), dict)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review"
            created = scaffold_review_dir(output)
            self.assertEqual(len(created), 14)
            self.assertTrue(all(path.read_bytes().strip() for path in created))


class QV1CSchemaManifestTests(unittest.TestCase):
    def test_schema10_manifest_passes_and_missing_trigger_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            repository = MaxControlRepository(path)
            repository.initialize()
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("DROP TRIGGER max_events_no_update")
                connection.commit()
            result = repository.verify_database()
            self.assertFalse(result["ok"])
            self.assertTrue(any("max_events_no_update" in issue for issue in result["issues"]))

    def test_schema10_manifest_rejects_definition_and_unexpected_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            repository = MaxControlRepository(path)
            repository.initialize()
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("DROP TRIGGER max_events_no_update")
                connection.execute(
                    "CREATE TRIGGER max_events_no_update AFTER INSERT ON max_events "
                    "BEGIN SELECT 1; END"
                )
                connection.execute(
                    "CREATE TABLE unexpected_qv1c_object(value TEXT NOT NULL)"
                )
                connection.commit()
            result = repository.verify_database()
            self.assertFalse(result["ok"])
            self.assertTrue(
                any("schema table unexpected: unexpected_qv1c_object" in issue for issue in result["issues"])
            )
            self.assertTrue(
                any("schema trigger definition mismatch: max_events_no_update" in issue for issue in result["issues"])
            )

    def test_future_ledger_is_rejected_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "future.db"
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TABLE max_schema_migrations(version INTEGER, name TEXT, applied_at TEXT)")
                connection.execute("INSERT INTO max_schema_migrations VALUES (11, 'future', 'now')")
                connection.commit()
            with self.assertRaises(MaxControlError):
                MaxControlRepository(path).initialize()


class QV1CReleaseTests(unittest.TestCase):
    @staticmethod
    def _source_tree_manifest() -> tuple[str, int]:
        root = Path.cwd()
        source_root = root / "src" / "research_kb" / "max_research"
        excluded = {"source_manifest_v1.json", "release_metadata_v1.json"}
        files = sorted(
            path for path in source_root.rglob("*")
            if path.is_file()
            and path.name not in excluded
            and "__pycache__" not in path.parts
            and path.suffix.casefold() not in {".pyc", ".pyo"}
        )
        digest = hashlib.sha256()
        for path in files:
            relative = path.relative_to(root).as_posix()
            digest.update(f"{relative}\n{hashlib.sha256(path.read_bytes()).hexdigest()}\n".encode("utf-8"))
        return digest.hexdigest(), len(files)

    @staticmethod
    def _create_schema9_database(path: Path) -> None:
        """Create a disposable schema-9 fixture from the reviewed 001-009 bytes."""

        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS max_schema_migrations(
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )
                """
            )
            for version, name, migration in migration_files()[:9]:
                for statement in _statements(migration.read_text(encoding="utf-8")):
                    connection.execute(statement)
                if version == 2:
                    _backfill_schema_v2(connection)
                elif version == 4:
                    _backfill_schema_v4(connection)
                elif version == 8:
                    _backfill_schema_v8(connection)
                connection.execute(
                    "INSERT INTO max_schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, "1970-01-01T00:00:00.000Z"),
                )
            connection.commit()

    def test_release_manifest_matches_all_fixed_migration_bytes(self) -> None:
        files = validate_migration_release()
        self.assertEqual(len(files), CONTROL_SCHEMA_VERSION)
        self.assertEqual([version for version, _, _ in files], list(range(1, CONTROL_SCHEMA_VERSION + 1)))

    def test_migration_release_manifest_rejects_disposable_byte_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "migrations"
            target.mkdir()
            for _, _, migration in migration_files():
                shutil.copy2(migration, target / migration.name)
            changed = target / "001_control_plane.sql"
            changed.write_bytes(changed.read_bytes() + b"\n-- qv1c disposable mismatch\n")
            with self.assertRaisesRegex(RuntimeError, "packaged migration bytes"):
                validate_migration_release(target)

    def test_schema9_fixture_upgrades_only_to_schema10(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schema9.db"
            self._create_schema9_database(path)
            result = MaxControlRepository(path).initialize()
            self.assertEqual(result["schema_version"], CONTROL_SCHEMA_VERSION)
            with closing(sqlite3.connect(path)) as connection:
                versions = [
                    row[0]
                    for row in connection.execute(
                        "SELECT version FROM max_schema_migrations ORDER BY version"
                    )
                ]
                self.assertEqual(versions, list(range(1, CONTROL_SCHEMA_VERSION + 1)))
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM max_live_dispatch_permits"
                    ).fetchone()[0],
                    0,
                )

    def test_release_metadata_distinguishes_candidate(self) -> None:
        metadata = json.loads(Path("src/research_kb/max_research/release_metadata_v1.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["package_version"], __version__)
        self.assertEqual(metadata["control_schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertEqual(metadata["core_schema_version"], 5)
        self.assertEqual(metadata["protocol"], "research-kb/v1")
        self.assertEqual(metadata["migration_count"], len(migration_files()))
        source_manifest = Path("src/research_kb/max_research/source_manifest_v1.json")
        self.assertEqual(metadata["source_manifest"], source_manifest.name)
        self.assertEqual(metadata["source_manifest_sha256"], hashlib.sha256(source_manifest.read_bytes()).hexdigest())
        source = json.loads(source_manifest.read_text(encoding="utf-8"))
        tree_hash, file_count = self._source_tree_manifest()
        self.assertEqual(source["control_schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertEqual(source["migration_count"], len(migration_files()))
        self.assertEqual(source["source_tree_sha256"], tree_hash)
        self.assertEqual(source["source_file_count"], file_count)

    def test_docs_and_release_manifests_match_current_contract(self) -> None:
        pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], __version__)
        release = json.loads(
            Path("src/research_kb/max_research/migration_release_manifest_v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(release["control_schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertEqual(len(release["migrations"]), CONTROL_SCHEMA_VERSION)
        self.assertEqual(
            release["migrations"][6]["name"],
            "007_mr2b0r_authority_budget_closure.sql",
        )
        self.assertEqual(
            release["migrations"][9]["name"],
            "010_mr2b1a_live_dispatch_permit.sql",
        )
        self.assertEqual(
            release["migrations"][10]["name"],
            "011_mr2b2_live_authorization_bundle.sql",
        )
        self.assertEqual(
            release["migrations"][11]["name"],
            "012_mr3_orchestration_acquisition.sql",
        )
        docs = [
            Path("README.md"),
            Path("docs/max-research-persistence.md"),
            Path("docs/max-research-control-plane.md"),
            Path("docs/max-research-live-provider.md"),
        ]
        for document in docs:
            text = document.read_text(encoding="utf-8")
            self.assertNotIn("007_mr2b0r1_runner_authority.sql", text)
            self.assertIn("007_mr2b0r_authority_budget_closure.sql", text)
            self.assertIn("010_mr2b1a_live_dispatch_permit.sql", text)
        readme = Path("README.md").read_text(encoding="utf-8")
        self.assertIn("MR-2B2", readme)
        self.assertIn("MR-3", readme)


if __name__ == "__main__":
    unittest.main()
