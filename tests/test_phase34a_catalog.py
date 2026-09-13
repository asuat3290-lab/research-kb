from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from research_kb.catalog import CatalogError, CatalogInterrupted, CatalogScanner
from research_kb.cli import main as cli_main
from research_kb.mcp_server import TOOL_NAMES


class Phase34ACatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.first = self.root / "\u7b2c\u4e00\u6839"
        self.second = self.root / "\u7b2c\u4e8c\u6839"
        self.output = self.root / "catalog-output"
        self.first.mkdir()
        self.second.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_text(self, root: Path, relative: str, text: str) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _write_fixture_set(self) -> None:
        self._write_text(self.first, "\u5b66\u672f/unique-one.md", "\u4e2d\u6587\u6765\u6e90\u4e00\uff1a\u5236\u5ea6\u7ed3\u6784\u4e0e\u52b3\u52a8\u63a7\u5236\u3002" * 6)
        self._write_text(self.first, "\u5b66\u672f/unique-two.md", "English source two: dependency and control." * 5)
        duplicate = "same source text for exact duplicate testing."
        self._write_text(self.first, "\u5b66\u672f/paper.md", duplicate)
        self._write_text(self.second, "\u5b66\u672f/paper-copy.md", duplicate)
        self._write_text(self.first, "same-size-a.txt", "AAAA-constant-size")
        self._write_text(self.first, "same-size-b.txt", "BBBB-constant-size")
        self._write_text(self.first, "coursework/homework.md", "Private unpublished course work.")
        self._write_text(self.first, "empty.txt", "")
        bad = self.first / "bad-encoding.txt"
        bad.write_bytes(bytes([0xff, 0xfe, 0x00, 0x80]))
        (self.first / "slides.pptx").write_bytes(b"not directly supported")
        (self.first / "image.png").write_bytes(b"PNG fixture")
        (self.first / "tool.exe").write_bytes(b"software fixture")
        (self.first / "broken.docx").write_bytes(b"not a zip")
        (self.first / "encrypted.pdf").write_bytes(b"%PDF-1.7\n/Encrypt 7 0 R")
        valid = self.first / "valid.docx"
        with zipfile.ZipFile(valid, "w") as archive:
            archive.writestr("word/document.xml", "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body><w:p><w:r><w:t>Valid DOCX text</w:t></w:r></w:p></w:body></w:document>")
        outside = self.root / "outside.txt"
        outside.write_text("outside root must not be read", encoding="utf-8")
        link = self.first / "escape-link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.symlink_available = False
        else:
            self.symlink_available = True

    def _scan(self, *, candidate_limit: int = 10, stop_after: int | None = None) -> dict:
        scanner = CatalogScanner(
            [("learning_materials", self.first), ("learning_materials_20", self.second)],
            self.output,
            candidate_limit=candidate_limit,
            checkpoint_interval=2,
        )
        return scanner.scan(stop_after=stop_after)

    def _records(self) -> list[dict]:
        path = self.output / "catalog.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def test_full_catalog_classifies_duplicates_privacy_and_never_publishes_paths_or_text(self) -> None:
        self._write_fixture_set()
        summary = self._scan()
        records = self._records()
        self.assertEqual(set(summary["roots"]), {"learning_materials", "learning_materials_20"})
        self.assertGreaterEqual(summary["totals"]["file_count"], 12)
        self.assertGreaterEqual(summary["exact_duplicate_group_count"], 1)
        self.assertGreaterEqual(summary["possible_duplicate_group_count"], 1)
        self.assertGreaterEqual(summary["privacy_review_count"], 1)
        self.assertGreaterEqual(summary["media_count"], 1)
        self.assertGreaterEqual(summary["software_cache_count"], 1)
        statuses = summary["totals"]["technical_status_counts"]
        self.assertIn("needs_extraction_review", statuses)
        self.assertIn("corrupt_or_unreadable", statuses)
        self.assertIn("encrypted", statuses)
        self.assertTrue(any(record["selection_status"] == "candidate" for record in records))
        if self.symlink_available:
            link_record = next(record for record in records if record["relative_path"] == "escape-link.txt")
            self.assertEqual(link_record["file_kind"], "link")
            self.assertFalse(any(record["relative_path"] == "outside.txt" for record in records))
        root_text = str(self.first.resolve())
        for path in self.output.glob("*"):
            if not path.is_file() or path.name == "root-map.local.json":
                continue
            content = path.read_text(encoding="utf-8")
            self.assertNotIn(root_text, content)
            self.assertNotIn("\u4e2d\u6587\u6765\u6e90\u4e00\uff1a\u5236\u5ea6\u7ed3\u6784\u4e0e\u52b3\u52a8\u63a7\u5236\u3002", content)
        self.assertTrue((self.output / "first-batch-manifest.dry-run.json").exists())
        self.assertTrue((self.output / "storage-forecast.json").exists())
        self.assertTrue((self.output / "CATALOG-RUNBOOK.md").exists())
        self.assertEqual(summary["dry_run"]["total"], summary["first_batch_candidate_count"])
        self.assertEqual(summary["dry_run"]["failed"], 0)
        self.assertFalse((self.output / "data" / "research.db").exists())

    def test_incremental_scan_records_new_modified_unchanged_and_removed(self) -> None:
        stable = self._write_text(self.first, "stable.md", "stable source")
        changed = self._write_text(self.first, "changed.md", "old source")
        removed = self._write_text(self.first, "removed.md", "removed source")
        self._scan(candidate_limit=5)
        before = {record["relative_path"]: record for record in self._records()}
        changed.write_text("new source with changed content", encoding="utf-8")
        os.utime(changed, None)
        removed.unlink()
        self._write_text(self.second, "new/\u65b0\u589e.md", "new source after first scan")
        summary = self._scan(candidate_limit=5)
        after = {record["relative_path"]: record for record in self._records()}
        self.assertEqual(after["stable.md"]["change_state"], "unchanged")
        self.assertEqual(after["changed.md"]["change_state"], "modified")
        self.assertEqual(after["removed.md"]["change_state"], "removed")
        self.assertEqual(after["new/\u65b0\u589e.md"]["change_state"], "new")
        self.assertEqual(before["stable.md"]["catalog_record_id"], after["stable.md"]["catalog_record_id"])
        self.assertIn("change_state_counts", summary["totals"])

    def test_interruption_recovery_uses_partial_state_and_atomic_final_catalog(self) -> None:
        for index in range(5):
            self._write_text(self.first, f"batch-{index}.md", f"batch source {index}")
        with self.assertRaises(CatalogInterrupted):
            self._scan(candidate_limit=4, stop_after=2)
        state = json.loads((self.output / "scan-state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["status"], "interrupted")
        self.assertFalse((self.output / "catalog.jsonl").exists())
        summary = self._scan(candidate_limit=4)
        self.assertTrue(summary["recovery"]["resumed_from_previous"])
        self.assertTrue((self.output / "catalog.jsonl").exists())
        self.assertEqual(json.loads((self.output / "scan-state.json").read_text(encoding="utf-8"))["status"], "complete")

    def test_source_content_and_mtime_remain_unchanged_and_output_rejects_overlap(self) -> None:
        path = self._write_text(self.first, "original.md", "original content")
        before_content = path.read_bytes()
        before_mtime = path.stat().st_mtime_ns
        self._scan(candidate_limit=2)
        self.assertEqual(path.read_bytes(), before_content)
        self.assertEqual(path.stat().st_mtime_ns, before_mtime)
        with self.assertRaises(CatalogError):
            CatalogScanner([("root", self.first)], self.first / "catalog-inside-root")

    def test_admin_cli_catalog_scan_returns_aggregate_only(self) -> None:
        self._write_text(self.first, "cli.md", "CLI catalog source")
        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = [
            "research-kb", "catalog", "scan",
            "--root", f"first={self.first}",
            "--root", f"second={self.second}",
            "--output", str(self.output),
            "--candidate-limit", "2",
            "--checkpoint-interval", "1",
        ]
        with patch.object(sys, "argv", argv), redirect_stdout(stdout), redirect_stderr(stderr):
            cli_main()
        result = json.loads(stdout.getvalue())
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"]["first_batch_candidate_count"], 1)
        self.assertIn("catalog_progress", stderr.getvalue())
        self.assertNotIn(str(self.first), stdout.getvalue())
        self.assertNotIn(str(self.first), stderr.getvalue())

    def test_storage_forecast_has_explicit_ordered_ranges_and_mcp_stays_at_twelve(self) -> None:
        self._write_text(self.first, "forecast.md", "forecast text" * 20)
        summary = self._scan(candidate_limit=2)
        forecast = json.loads((self.output / "storage-forecast.json").read_text(encoding="utf-8"))
        for section in ("native_text_ingest", "ocr_scenario", "ocr_derivative_scenario"):
            values = forecast[section].get("database_bytes") or forecast[section].get("database_plus_sidecars_bytes")
            self.assertLessEqual(values["low"], values["expected"])
            self.assertLessEqual(values["expected"], values["high"])
        self.assertEqual(len(TOOL_NAMES), 12)
        self.assertEqual(summary["first_batch_candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
