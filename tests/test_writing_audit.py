from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from research_kb.writing_audit import (
    audit_document,
    build_public_draft,
    check_public_parity,
    detect_line_endings,
    line_ending_report,
    main as audit_main,
    normalize_line_endings,
    run_compression_review,
    strip_writing_annotations,
)
from research_kb.writing_policy import load_writing_policy


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "writing"
TEMPLATES = REPO_ROOT / "docs" / "templates"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class WritingAuditEngineTests(unittest.TestCase):
    def test_forbidden_terms_scan_visible_text_including_references_and_footnotes(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "正文包含 REVIEW 字样。",
                "# 导论",
                "```text",
                "REVIEW",
                "```",
                "行内 `Claim` 和注释 <!-- 锚点 --> 不触发。",
                "# 结论",
                "结论正文正常。",
                "# 参考文献",
                "参考文献包含 Admin CLI 与 v6.4。",
                "[^1]: APPROVED 脚注说明。",
            ]
        )
        result = audit_document(text, profile="academic_paper")
        self.assertGreaterEqual(len(result.errors), 3)
        self.assertGreaterEqual(len(result.approval_blockers), 3)
        self.assertEqual(result.errors[0]["rule_id"], "academic_paper_forbidden_system_state")
        self.assertIn("REVIEW", result.errors[0]["snippet"])

    def test_system_metadata_leakage_in_footnotes_and_bibliography(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "摘要正文。",
                "",
                "# 导论",
                "正文。",
                "",
                "# 结论",
                "结论。",
                "",
                "# 脚注",
                "[^1]: 已 exact-quote 核验，ve_ab12cd34ef56；OCR-normalized。",
                "",
                "# 参考文献",
                "1. 示例作者：《示例书名》，数字化文本（PENDING_PAGE）。",
            ]
        )
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        rule_ids = {finding["rule_id"] for finding in result.errors}
        self.assertIn("academic_paper_forbidden_system_state", rule_ids)
        self.assertIn("SYSTEM_METADATA_LEAKAGE", rule_ids)

    def test_bibliography_completeness_review(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "摘要正文。",
                "",
                "# 导论",
                "正文。",
                "",
                "# 结论",
                "结论。",
                "",
                "# 参考文献",
                "1. 示例作者：《示例书名》，人民文学出版社，2018。",
                "2. 另一作者：《缺出版信息的书》，数字化文本。",
            ]
        )
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        findings = [
            finding
            for finding in result.review_items
            if finding["rule_id"] == "bibliography_completeness"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("publisher", findings[0]["message"])
        self.assertIn("year", findings[0]["message"])

    def test_budget_warning(self) -> None:
        policy = copy.deepcopy(load_writing_policy())
        policy["profiles"]["academic_paper"]["budget"] = {"min_chars": 0, "max_chars": 100}
        result = audit_document("x" * 200, policy=policy, profile="academic_paper")
        rule_ids = {finding["rule_id"] for finding in result.warnings}
        self.assertIn("budget_soft_limit", rule_ids)

    def test_patch_section_numbering(self) -> None:
        text = "# 第一章\n\n## 十三、补丁\n\n## 十二、倒序\n"
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        rule_ids = {finding["rule_id"] for finding in result.warnings}
        self.assertIn("patch_section_numbering", rule_ids)

    def test_required_sections(self) -> None:
        result = audit_document("# 导论\n\n只有导论。\n", profile="academic_paper")
        error_messages = [finding["message"] for finding in result.errors]
        self.assertTrue(any("摘要" in message for message in error_messages))
        self.assertTrue(any("参考文献" in message for message in error_messages))
        review_messages = [finding["message"] for finding in result.review_items]
        self.assertTrue(any("结论" in message for message in review_messages))

    def test_empty_abstract_is_error(self) -> None:
        text = "# 摘要\n\n# 导论\n\n正文。\n\n# 结论\n\n结论。\n\n# 参考文献\n\n参考条目。\n"
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        self.assertTrue(
            any(
                finding["rule_id"] == "required_section_content"
                and "摘要" in finding["message"]
                for finding in result.errors
            )
        )
        self.assertTrue(
            any(
                finding["rule_id"] == "required_section_content"
                for finding in result.approval_blockers
            )
        )

    def test_empty_references_is_error(self) -> None:
        text = "# 摘要\n\n摘要正文。\n\n# 导论\n\n正文。\n\n# 结论\n\n结论。\n\n# 参考文献\n"
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        self.assertTrue(
            any(finding["rule_id"] == "bibliography_nonempty" for finding in result.errors)
        )
        self.assertTrue(
            any(
                finding["rule_id"] == "required_section_content"
                and "参考文献" in finding["message"]
                for finding in result.errors
            )
        )

    def test_footnote_missing_definition(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "摘要正文。[^1]",
                "",
                "# 导论",
                "正文。",
                "",
                "# 结论",
                "结论。",
                "",
                "# 脚注",
                "",
                "# 参考文献",
                "参考条目。",
            ]
        )
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        self.assertTrue(
            any(
                finding["rule_id"] == "footnote_integrity"
                and "[^1]" in finding["message"]
                for finding in result.errors
            )
        )
        self.assertTrue(
            any(
                finding["rule_id"] == "footnote_integrity"
                for finding in result.approval_blockers
            )
        )

    def test_footnote_duplicate_definition(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "摘要正文。[^1]",
                "",
                "# 导论",
                "正文。",
                "",
                "# 结论",
                "结论。",
                "",
                "# 脚注",
                "[^1]: 定义一。",
                "[^1]: 定义二。",
                "",
                "# 参考文献",
                "参考条目。",
            ]
        )
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        self.assertTrue(
            any(
                finding["rule_id"] == "footnote_integrity"
                and "重复" in finding["message"]
                for finding in result.errors
            )
        )

    def test_footnote_orphan_definition_warns(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "摘要正文。",
                "",
                "# 导论",
                "正文。",
                "",
                "# 结论",
                "结论。",
                "",
                "# 脚注",
                "[^1]: 定义一。",
                "",
                "# 参考文献",
                "参考条目。",
            ]
        )
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        self.assertTrue(
            any(
                finding["rule_id"] == "footnote_integrity"
                and "未被引用" in finding["message"]
                for finding in result.warnings
            )
        )

    def test_footnote_multiline_definition_is_valid(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "摘要正文。[^1]",
                "",
                "# 导论",
                "正文。",
                "",
                "# 结论",
                "结论。",
                "",
                "# 脚注",
                "[^1]: 定义首行。",
                "    续行内容。",
                "",
                "# 参考文献",
                "参考条目。",
            ]
        )
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        self.assertFalse(
            any(finding["rule_id"] == "footnote_integrity" for finding in result.errors)
        )
        self.assertFalse(
            any(finding["rule_id"] == "footnote_integrity" for finding in result.warnings)
        )

    def test_footnotes_inside_code_blocks_are_ignored(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "摘要正文。",
                "",
                "# 导论",
                "```text",
                "[^1]: 代码脚注。",
                "[^1] 代码引用",
                "```",
                "正文。",
                "",
                "# 结论",
                "结论。",
                "",
                "# 脚注",
                "",
                "# 参考文献",
                "参考条目。",
            ]
        )
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        self.assertFalse(
            any(finding["rule_id"] == "footnote_integrity" for finding in result.errors)
        )
        self.assertFalse(
            any(finding["rule_id"] == "footnote_integrity" for finding in result.warnings)
        )

    def test_line_ending_detection(self) -> None:
        self.assertEqual(
            detect_line_endings(b"a\nb\n"),
            {"mixed": False, "dominant": "lf", "styles": ["lf"]},
        )
        self.assertEqual(
            detect_line_endings(b"a\r\nb\r\n"),
            {"mixed": False, "dominant": "crlf", "styles": ["crlf"]},
        )
        self.assertEqual(
            detect_line_endings(b"a\nb\r\n"),
            {"mixed": True, "dominant": "lf", "styles": ["lf", "crlf"]},
        )
        self.assertEqual(
            detect_line_endings(b"a\rb\r"),
            {"mixed": False, "dominant": "cr", "styles": ["cr"]},
        )
        self.assertEqual(
            detect_line_endings(b""),
            {"mixed": False, "dominant": None, "styles": []},
        )

    def test_normalize_line_endings(self) -> None:
        self.assertEqual(normalize_line_endings("a\nb\n", "crlf"), "a\r\nb\r\n")
        self.assertEqual(normalize_line_endings("a\r\nb\r\n", "lf"), "a\nb\n")
        self.assertEqual(normalize_line_endings("a\nb", "crlf"), "a\r\nb")
        self.assertEqual(normalize_line_endings("a\r\nb\r\nc\n", "lf"), "a\nb\nc\n")

    def test_line_ending_report_mixed_and_mismatch(self) -> None:
        snapshot = {
            "line_endings": {
                "default": "lf",
                "mixed_severity": "error",
                "mismatch_severity": "warning",
            }
        }
        mixed = line_ending_report(b"a\nb\r\n", snapshot)
        self.assertEqual(mixed["severity"], "error")
        self.assertEqual(mixed["message"], "MIXED_LINE_ENDINGS")
        mismatch = line_ending_report(b"a\r\nb\r\n", snapshot)
        self.assertEqual(mismatch["severity"], "warning")
        self.assertEqual(mismatch["message"], "LINE_ENDINGS_MISMATCH")
        ok = line_ending_report(b"a\nb\n", snapshot)
        self.assertEqual(ok["severity"], "ok")

    def test_public_parity_ignores_pure_crlf_difference(self) -> None:
        text = "\n".join(
            [
                "# \u6458\u8981",
                "\u6458\u8981\u6b63\u6587\u3002",
                "",
                "# \u5bfc\u8bba",
                "\u6b63\u6587\u3002",
                "",
                "# \u7ed3\u8bba",
                "\u7ed3\u8bba\u3002",
                "",
                "# \u53c2\u8003\u6587\u732e",
                "\u53c2\u8003\u6587\u732e\u3002",
            ]
        )
        public = normalize_line_endings(text, "crlf")
        ok, problems = check_public_parity(text, public)
        self.assertTrue(ok, problems)

    def test_public_draft_writes_crlf_without_mutating_source(self) -> None:
        text = "\n".join(
            [
                "# \u6458\u8981",
                "\u6458\u8981\u6b63\u6587\u3002",
                "",
                "# \u5bfc\u8bba",
                "\u6b63\u6587\u3002",
                "",
                "# \u7ed3\u8bba",
                "\u7ed3\u8bba\u3002",
                "",
                "# \u53c2\u8003\u6587\u732e",
                "\u53c2\u8003\u6587\u732e\u3002",
            ]
        ) + "\n"
        public, report = build_public_draft(text, line_ending="crlf")
        self.assertEqual(report["line_ending"], "crlf")
        self.assertTrue(report["line_ending_normalized"])
        self.assertIn("\r\n", public)
        self.assertNotIn("\n", public.replace("\r\n", ""))
        self.assertEqual(text, "\n".join(text.splitlines()) + "\n")

    def test_public_export_build_and_parity(self) -> None:
        text = "\n".join(
            [
                "# 摘要",
                "摘要正文。[^1]",
                "",
                "# 导论",
                "正文。",
                "",
                "# 结论",
                "结论。",
                "",
                "# 脚注",
                "[^1]: 定义。",
                "",
                "# 参考文献",
                "参考条目。",
            ]
        )
        public, report = build_public_draft(text)
        ok, problems = check_public_parity(text, public)
        self.assertTrue(ok, problems)
        self.assertNotIn("writing:", public)
        self.assertNotIn("<!--", public)
        tampered = public.replace("# 结论", "# 结论已被篡改", 1)
        ok_tampered, tampered_problems = check_public_parity(text, tampered)
        self.assertFalse(ok_tampered)
        self.assertTrue(any("标题" in problem for problem in tampered_problems))

    def test_argument_gain_managed_draft(self) -> None:
        text = "# 导论\n\n## 1. 研究问题\n\n正文。\n"
        missing = audit_document(text, profile="academic_paper", managed_draft=True)
        self.assertTrue(
            any(
                finding["rule_id"] == "argument_gain_coverage"
                for finding in missing.warnings
            )
        )

        annotated = (
            "# 导论\n\n## 1. 研究问题\n\n"
            "<!-- writing:\n"
            "section_id: 1. 研究问题\n"
            "argument_gain:\n"
            "  - new_evidence\n"
            "-->\n\n正文。\n"
        )
        covered = audit_document(annotated, profile="academic_paper", managed_draft=True)
        self.assertFalse(
            any(
                finding["rule_id"] == "argument_gain_coverage"
                for finding in covered.warnings
            )
        )

        invalid = (
            "# 导论\n\n## 1. 研究问题\n\n"
            "<!-- writing:\n"
            "section_id: 1. 研究问题\n"
            "argument_gain:\n"
            "  - invented_gain\n"
            "-->\n\n正文。\n"
        )
        bad_gain = audit_document(invalid, profile="academic_paper", managed_draft=True)
        self.assertTrue(
            any(
                "unknown gain" in finding["message"]
                for finding in bad_gain.warnings
            )
        )

    def test_external_draft_skips_argument_gain(self) -> None:
        text = "# 导论\n\n## 1. 研究问题\n\n正文。\n"
        result = audit_document(text, profile="academic_paper", managed_draft=False)
        self.assertFalse(
            any(
                finding["rule_id"] == "argument_gain_coverage"
                for finding in result.warnings
            )
        )

    def test_sidecar_annotations(self) -> None:
        text = "# 导论\n\n## 一、核心概念\n\n正文。\n"
        sidecar = {"一、核心概念": ["new_evidence", "concept_distinction"]}
        result = audit_document(
            text,
            profile="academic_paper",
            sidecar_annotations=sidecar,
        )
        self.assertFalse(
            any(
                finding["rule_id"] == "argument_gain_coverage"
                for finding in result.warnings
            )
        )
        self.assertEqual(len(result.annotations), 1)

    def test_strip_writing_annotations(self) -> None:
        text = "# 导论\n\n## 1. 研究问题\n\n<!-- writing:\nsection_id: 1. 研究问题\nargument_gain:\n  - new_evidence\n-->\n\n正文。\n"
        stripped = strip_writing_annotations(text)
        self.assertNotIn("writing:", stripped)
        self.assertNotIn("<!--", stripped)
        self.assertIn("## 1. 研究问题", stripped)
        self.assertIn("正文。", stripped)

    def test_compression_review_duplicates_and_limit_echo(self) -> None:
        repeated = "这是同一句重复出现的完整表述。"
        text = "\n".join([repeated, repeated, repeated, "不能证明谱系，只能视为功能比较。"] * 2)
        result = run_compression_review(text, profile="academic_paper")
        rule_ids = {finding["rule_id"] for finding in result.review_items}
        self.assertIn("compression_review_duplicates", rule_ids)
        self.assertIn("compression_review_limits", rule_ids)

    def test_conclusion_status_is_blocker_in_compression_review(self) -> None:
        text = "# 结论\n\n本轮核验了 3 条引文，等待人工批准。\n"
        result = run_compression_review(text, profile="academic_paper")
        self.assertTrue(
            any(
                finding["rule_id"] == "compression_review_conclusion_status"
                for finding in result.approval_blockers
            )
        )

    def test_profile_differentiation(self) -> None:
        a = audit_document(_read("A-negative.md"), profile="academic_paper")
        b = audit_document(_read("B-negative.md"), profile="method_appendix")
        c = audit_document(_read("C-positive.md"), profile="technical_report")
        self.assertTrue(a.errors)
        self.assertTrue(a.approval_blockers)
        self.assertTrue(b.errors)
        self.assertFalse(b.approval_blockers)
        self.assertFalse(c.errors)
        self.assertFalse(c.warnings)
        self.assertFalse(c.review_items)
        self.assertFalse(c.approval_blockers)

    def test_positive_fixtures_have_no_errors_or_blockers(self) -> None:
        for profile, name in (
            ("academic_paper", "A-positive.md"),
            ("method_appendix", "B-positive.md"),
            ("technical_report", "C-positive.md"),
        ):
            result = audit_document(_read(name), profile=profile)
            self.assertEqual(result.errors, [], name)
            self.assertEqual(result.approval_blockers, [], name)

    def test_templates_are_clean(self) -> None:
        result = audit_document(
            (TEMPLATES / "A-academic-paper.md").read_text(encoding="utf-8"),
            profile="academic_paper",
        )
        self.assertEqual(result.errors, [])
        self.assertEqual(result.approval_blockers, [])
        b = audit_document(
            (TEMPLATES / "B-method-appendix.md").read_text(encoding="utf-8"),
            profile="method_appendix",
        )
        self.assertEqual(b.errors, [])
        self.assertEqual(b.approval_blockers, [])
        c = audit_document(
            (TEMPLATES / "C-technical-report.md").read_text(encoding="utf-8"),
            profile="technical_report",
        )
        self.assertEqual(c.errors, [])
        self.assertEqual(c.approval_blockers, [])


class WritingAuditCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_check_strict_exits_one_with_blockers(self) -> None:
        source = self._write("bad.md", "# 摘要\n\n本轮核验了 1 条引文。\n")
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                audit_main([str(source), "--check", "--strict"])
        self.assertEqual(caught.exception.code, 1)

    def test_export_removes_annotations(self) -> None:
        source = self._write(
            "draft.md",
            "# 导论\n\n## 1. 研究问题\n\n"
            "<!-- writing:\nsection_id: 1. 研究问题\nargument_gain:\n  - new_evidence\n-->\n\n正文。\n",
        )
        out = self.root / "exported.md"
        audit_main([str(source), "--export", str(out)])
        self.assertTrue(out.exists())
        self.assertNotIn("writing:", out.read_text(encoding="utf-8"))

    def test_export_writes_build_report(self) -> None:
        source = self._write(
            "draft.md",
            "# 摘要\n\n摘要正文。\n\n# 导论\n\n正文。\n\n# 结论\n\n结论。\n\n# 参考文献\n\n参考条目。\n",
        )
        out = self.root / "public.md"
        report_out = self.root / "build.json"
        audit_main(
            [
                str(source),
                "--export",
                str(out),
                "--export-build-report",
                str(report_out),
            ]
        )
        self.assertTrue(out.exists())
        build = json.loads(report_out.read_text(encoding="utf-8"))
        self.assertTrue(build["parity"]["ok"])

    def test_export_line_ending_flag(self) -> None:
        source = self._write("draft.md", "# Title\n\nBody.\n")
        out = self.root / "public-crlf.md"
        report_out = self.root / "build-crlf.json"
        audit_main(
            [
                str(source),
                "--export",
                str(out),
                "--export-build-report",
                str(report_out),
                "--line-ending",
                "crlf",
            ]
        )
        raw = out.read_bytes()
        self.assertIn(b"\r\n", raw)
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        build = json.loads(report_out.read_text(encoding="utf-8"))
        self.assertEqual(build["line_ending"], "crlf")
        self.assertTrue(build["line_ending_normalized"])

    def test_manifest_writes_json_result(self) -> None:
        source = self._write("ok.md", "# 摘要\n\n正文。\n")
        out = self.root / "manifest.json"
        audit_main([str(source), "--manifest", str(out)])
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(set(data), {
            "profile",
            "policy_version",
            "policy_fingerprint",
            "policy_snapshot",
            "errors",
            "warnings",
            "review_items",
            "approval_blockers",
            "scanned_chars",
            "ignored_chars",
            "annotations",
            "managed_draft",
            "mode",
            "source_path",
        })


if __name__ == "__main__":
    unittest.main()
