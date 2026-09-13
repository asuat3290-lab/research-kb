from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from research_kb.catalog import CatalogScanner, _classify, _pdf_probe_work, _probe_pdf
from research_kb.mcp_server import TOOL_NAMES


class CatalogQualityPhase341Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "materials"
        self.output = Path(self.temp.name) / "catalog"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, content: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def scan(self, *, candidate_limit: int = 20, max_hash_bytes: int = 512 * 1024 * 1024, policy_path: Path | None = None) -> dict:
        return CatalogScanner(
            [("materials", self.root)],
            self.output,
            candidate_limit=candidate_limit,
            max_hash_bytes=max_hash_bytes,
            checkpoint_interval=3,
            policy_path=policy_path,
        ).scan()

    def records(self) -> list[dict]:
        return [json.loads(line) for line in (self.output / "catalog.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_policy_terms_and_generated_repository_outputs_are_not_ready(self) -> None:
        self.write("个人/学习档案.md", "private study notes")
        self.write("私人/日志.md", "private log")
        self.write(".mimocode/README.md", "tool instructions")
        self.write("src/packages/example.py", "print('code')")
        self.write("build/output.txt", "generated")
        self.write("ocr_output/page_0001.txt", "ocr fragment")
        self.write("ordinary.md", "ordinary source")
        summary = self.scan()
        records = self.records()
        by_path = {record["relative_path"]: record for record in records}
        self.assertEqual(by_path["个人/学习档案.md"]["privacy_classification"], "personal_material_review")
        self.assertEqual(by_path["私人/日志.md"]["privacy_classification"], "personal_material_review")
        self.assertTrue(by_path[".mimocode/README.md"]["code_repository"])
        self.assertTrue(by_path["src/packages/example.py"]["code_repository"])
        self.assertTrue(by_path["build/output.txt"]["possible_generated_derivative"])
        self.assertTrue(by_path["ocr_output/page_0001.txt"]["ocr_page_fragment"])
        self.assertFalse(any(record.get("candidate_kind") == "ready" for record in records))
        self.assertGreaterEqual(summary["personal_material_review_count"], 2)
        self.assertGreaterEqual(summary["generated_derivative_count"], 2)

    def test_docx_creator_and_filename_title_have_unverified_provenance(self) -> None:
        path = self.root / "book-title.docx"
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("word/document.xml", "<w:document xmlns:w='urn:w'><w:body><w:p><w:r><w:t>Text</w:t></w:r></w:p></w:body></w:document>")
            archive.writestr("docProps/core.xml", "<cp:coreProperties xmlns:cp='urn:cp' xmlns:dc='urn:dc'><dc:title>Embedded title</dc:title><dc:creator>WindowsUser</dc:creator></cp:coreProperties>")
        self.scan()
        record = next(item for item in self.records() if item["relative_path"] == "book-title.docx")
        self.assertEqual(record["inferred_title"], "book-title")
        self.assertEqual(record["metadata_candidates"].get("file_creator"), "WindowsUser")
        self.assertNotIn("creator", record["metadata_candidates"])
        self.assertTrue(all(value == "embedded_file_creator_unverified" for value in record["metadata_provenance"].values()))
        self.assertNotEqual(record.get("candidate_kind"), "ready")

    def test_epub_creator_is_normalized_to_authors_in_candidates_and_provenance(self) -> None:
        path = self.root / "embedded-book.epub"
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("mimetype", "application/epub+zip")
            archive.writestr("META-INF/container.xml", "<container version='1.0' xmlns='urn:oasis:names:tc:opendocument:xmlns:container'><rootfiles><rootfile full-path='OEBPS/content.opf' media-type='application/oebps-package+xml'/></rootfiles></container>")
            archive.writestr("OEBPS/content.opf", "<package xmlns='http://www.idpf.org/2007/opf' version='3.0' xmlns:dc='http://purl.org/dc/elements/1.1/'><metadata><dc:title>Embedded Book</dc:title><dc:creator>Test Author</dc:creator></metadata><manifest><item id='c1' href='chapter.xhtml' media-type='application/xhtml+xml'/></manifest><spine><itemref idref='c1'/></spine></package>")
            archive.writestr("OEBPS/chapter.xhtml", "<html xmlns='http://www.w3.org/1999/xhtml'><body><p>Readable embedded content.</p></body></html>")
        self.scan()
        record = next(item for item in self.records() if item["relative_path"] == "embedded-book.epub")
        self.assertEqual(record["metadata_candidates"]["authors"], ["Test Author"])
        self.assertNotIn("creator", record["metadata_candidates"])
        self.assertEqual(record["metadata_candidates"].get("title"), "Embedded Book")
        self.assertEqual(record["metadata_provenance"].get("authors"), "embedded_bibliographic")
        self.assertEqual(record["metadata_provenance"].get("title"), "embedded_bibliographic")
        self.assertEqual(record["source_type_candidate"], "book")
        self.assertNotIn("author_or_editor_missing_or_unverified", record.get("technical_reasons", []))
        _, metadata_reasons = CatalogScanner._metadata_ready(record)
        self.assertNotIn("author_or_editor_missing_or_unverified", metadata_reasons)

    def test_duplicate_states_do_not_overwrite_technical_status(self) -> None:
        self.write("same-a.txt", "AAAA-constant-size")
        self.write("same-b.txt", "BBBB-constant-size")
        self.write("exact-a.md", "same exact body")
        self.write("exact-b.md", "same exact body")
        self.write("pending-a.txt", "P" * 100)
        self.write("pending-b.txt", "P" * 100)
        summary = self.scan(max_hash_bytes=1)
        records = {record["relative_path"]: record for record in self.records()}
        self.assertEqual(records["same-a.txt"]["duplicate_status"], "none")
        self.assertEqual(records["same-b.txt"]["duplicate_status"], "none")
        self.assertEqual(records["same-a.txt"]["duplicate_comparison_bucket"], records["same-b.txt"]["duplicate_comparison_bucket"])
        self.assertNotEqual(records["same-a.txt"]["technical_status"], "possible_duplicate")
        self.assertEqual(records["exact-a.md"]["duplicate_status"], "possible_duplicate")
        self.assertEqual(records["exact-b.md"]["duplicate_status"], "possible_duplicate")
        self.assertGreaterEqual(summary["size_only_comparison_group_count"], 1)
        self.assertGreaterEqual(summary["quick_possible_duplicate_group_count"], 1)

    def test_exact_full_sha_is_independent_status(self) -> None:
        self.write("exact-a.md", "same exact body")
        self.write("exact-b.md", "same exact body")
        self.scan()
        records = {record["relative_path"]: record for record in self.records()}
        self.assertEqual(records["exact-a.md"]["duplicate_status"], "exact_duplicate")
        self.assertEqual(records["exact-a.md"]["duplicate_group_id"], records["exact-b.md"]["duplicate_group_id"])
        self.assertNotEqual(records["exact-a.md"]["technical_status"], "exact_duplicate")

    def test_pdf_probe_pending_is_not_needs_ocr_zero(self) -> None:
        pdf = self.write("large.pdf", b"%PDF-1.7\n" + b"x" * 128)
        policy = json.loads((Path(__file__).parents[1] / "src" / "research_kb" / "catalog_policy.json").read_text(encoding="utf-8"))
        policy["forecast"]["pdf_max_probe_bytes"] = 64
        policy_path = Path(self.temp.name) / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        probe = _probe_pdf(pdf, policy)
        self.assertEqual(probe["probe"]["pdf_probe_status"], "probe_pending")
        self.assertEqual(probe["probe"]["ocr_status"], "probe_pending")
        summary = self.scan(policy_path=policy_path)
        self.assertEqual(summary["needs_ocr_count"], 0)
        self.assertGreaterEqual(summary["pdf_probe_pending_count"], 1)
        self.assertEqual(summary["pdf_ocr_status_counts"].get("probe_pending"), 1)
        self.assertFalse(any(item.get("candidate_kind") == "ready" for item in self.records() if item["extension"] == ".pdf"))

    def test_pdf_probe_wall_clock_timeout_returns_pending(self) -> None:
        pdf = self.write("slow.pdf", b"%PDF-1.7\n" + b"x" * 128)
        policy = json.loads((Path(__file__).parents[1] / "src" / "research_kb" / "catalog_policy.json").read_text(encoding="utf-8"))
        policy["forecast"]["pdf_probe_timeout_seconds"] = 0.1
        original_work = _pdf_probe_work

        def hanging_work(path: Path, payload_policy: dict) -> dict:
            import time
            time.sleep(5)
            return original_work(path, payload_policy)

        import research_kb.catalog as catalog
        catalog._pdf_probe_work = hanging_work
        try:
            probe = _probe_pdf(pdf, policy)
        finally:
            catalog._pdf_probe_work = original_work
        self.assertEqual(probe["status"], "pending")
        self.assertEqual(probe["probe"]["pdf_probe_status"], "probe_pending")
        self.assertEqual(probe["probe"]["probe_deferred_reason"], "pdf_probe_timeout")
        self.assertIn("pdf_probe_timeout", probe["reasons"])

    def test_forecast_has_fixed_marginal_stratification_and_no_padding(self) -> None:
        self.write("a.md", "text " * 100)
        self.write("b.txt", "text " * 100)
        summary = self.scan(candidate_limit=50)
        forecast = json.loads((self.output / "storage-forecast.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["first_batch_candidate_count"], 2)
        self.assertLess(summary["first_batch_candidate_count"], 50)
        self.assertIn("first_batch_forecast", forecast)
        self.assertIn("full_native_corpus_forecast", forecast)
        for section in (forecast["first_batch_forecast"], forecast["full_native_corpus_forecast"]):
            self.assertIn("fixed_schema_bytes", section)
            self.assertIn("marginal_data_bytes", section)
            self.assertIn("database_bytes", section)
            self.assertIn("wal_sidecar_bytes", section)
            self.assertIn("full_backup_bytes", section)
            self.assertIn("sample", section)
            self.assertIn(section["confidence"], {"low", "medium", "high"})
            self.assertLessEqual(section["database_bytes"]["low"], section["database_bytes"]["expected"])
            self.assertLessEqual(section["database_bytes"]["expected"], section["database_bytes"]["high"])
        self.assertEqual(len([line for line in (self.output / "first-batch-ready.jsonl").read_text(encoding="utf-8").splitlines() if line]), 0)
        self.assertEqual(len(TOOL_NAMES), 12)

    def test_policy_is_utf8_json_and_classification_is_configurable(self) -> None:
        policy_path = Path(__file__).parents[1] / "src" / "research_kb" / "catalog_policy.json"
        payload = json.loads(policy_path.read_text(encoding="utf-8"))
        self.assertIn("个人", payload["private_terms"])
        self.assertIn("本科阶段", payload["discovery_terms"])
        self.assertIn("forecast", payload)
        self.assertTrue(_classify("notes/普通.md", ".md", payload)["supported_by_current_ingest"])


if __name__ == "__main__":
    unittest.main()

