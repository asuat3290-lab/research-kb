from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .policy import PolicyError
from .writing_policy import (
    KNOWN_PROFILES,
    LINE_ENDINGS,
    load_writing_policy,
    policy_fingerprint,
    resolve_writing_policy,
    validate_resolved_policy,
)


_SEVERITY_BUCKETS = {
    "error": "errors",
    "warning": "warnings",
    "review": "review_items",
}
_BUCKET_SEVERITY = {
    "errors": "error",
    "warnings": "warning",
    "review_items": "review",
    "approval_blockers": "error",
}
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_CHAPTER_CN_RE = re.compile(r"第([一二三四五六七八九十百千]+)章")
_CHAPTER_EN_RE = re.compile(r"Chapter\s+(\d+)", re.IGNORECASE)
_NUMERIC_SECTION_RE = re.compile(r"^(\d{1,3})([\.、．:：]|\s)")
_CN_SECTION_RE = re.compile(r"^([一二三四五六七八九十百]+)、")
_CN_DIGITS = {
    "零": 0,
    "一": 1,
    "二": 2,
    "两": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
    "百": 100,
}
_REFERENCE_HEADING_RE = re.compile(
    r"^(#{1,6})\s*(参考文献|References|Bibliography)\s*$", re.IGNORECASE
)
_FOOTNOTE_DEF_RE = re.compile(r"^\[\^([^\]]+)\]:")
_FOOTNOTE_REF_RE = re.compile(r"\[\^([^\]]+)\](?!:)")
_WRITING_COMMENT_RE = re.compile(r"<!--\s*writing:.*?-->", re.S)
_LINE_ENDING_NAMES = {"lf": "\n", "crlf": "\r\n", "cr": "\r"}


@dataclass(frozen=True)
class AuditFinding:
    rule_id: str
    severity: str
    bucket: str
    line: int | None
    message: str
    snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "bucket": self.bucket,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class AuditResult:
    profile: str
    policy_version: str
    policy_snapshot: dict[str, Any]
    findings: tuple[AuditFinding, ...]
    scanned_chars: int
    ignored_chars: int
    annotations: tuple[dict[str, Any], ...]
    managed_draft: bool
    mode: str
    source_path: str | None = None
    policy_fingerprint: str = ""

    def _bucket_findings(self, bucket: str) -> list[dict[str, Any]]:
        return [finding.to_dict() for finding in self.findings if finding.bucket == bucket]

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "policy_version": self.policy_version,
            "policy_fingerprint": self.policy_fingerprint,
            "policy_snapshot": self.policy_snapshot,
            "errors": self._bucket_findings("errors"),
            "warnings": self._bucket_findings("warnings"),
            "review_items": self._bucket_findings("review_items"),
            "approval_blockers": self._bucket_findings("approval_blockers"),
            "scanned_chars": self.scanned_chars,
            "ignored_chars": self.ignored_chars,
            "annotations": list(self.annotations),
            "managed_draft": self.managed_draft,
            "mode": self.mode,
            "source_path": self.source_path,
        }

    @property
    def errors(self) -> list[dict[str, Any]]:
        return self._bucket_findings("errors")

    @property
    def warnings(self) -> list[dict[str, Any]]:
        return self._bucket_findings("warnings")

    @property
    def review_items(self) -> list[dict[str, Any]]:
        return self._bucket_findings("review_items")

    @property
    def approval_blockers(self) -> list[dict[str, Any]]:
        return self._bucket_findings("approval_blockers")


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return starts


def _line_at(offset: int, starts: list[int]) -> int:
    return bisect.bisect_right(starts, offset) - 1


def _merge_ranges(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    ordered = sorted((start, end) for start, end in ranges if end > start)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _line_masks(text: str, ignore: set[str]) -> list[list[tuple[int, int]]]:
    lines = text.splitlines()
    masks: list[list[tuple[int, int]]] = [[] for _ in lines]
    if not lines:
        return masks
    starts = _line_starts(text)

    if "code_blocks" in ignore:
        fence: str | None = None
        for index, line in enumerate(lines):
            stripped = line.strip()
            if fence is not None:
                masks[index].append((0, len(line)))
                if stripped.startswith(fence):
                    fence = None
                continue
            if stripped.startswith(("```", "~~~")):
                fence = stripped[:3]
                masks[index].append((0, len(line)))

    if "inline_code" in ignore:
        for index, line in enumerate(lines):
            for match in re.finditer(r"`[^`\n]+`", line):
                masks[index].append(match.span())

    if "html_comments" in ignore:
        for match in re.finditer(r"<!--.*?-->", text, re.S):
            start_line = _line_at(match.start(), starts)
            end_line = _line_at(match.end(), starts)
            for index in range(start_line, end_line + 1):
                line_start = starts[index]
                line_end = starts[index + 1] if index + 1 < len(starts) else len(text)
                overlap_start = max(match.start(), line_start) - line_start
                overlap_end = min(match.end(), line_end) - line_start
                if overlap_end > overlap_start:
                    masks[index].append((overlap_start, overlap_end))

    if "front_matter" in ignore:
        if lines and lines[0].strip() == "---":
            end = 1
            while end < len(lines) and lines[end].strip() != "---":
                end += 1
            for index in range(0, min(end + 1, len(lines))):
                masks[index].append((0, len(lines[index])))

    if "references" in ignore:
        reference_start: int | None = None
        for index, line in enumerate(lines):
            if _REFERENCE_HEADING_RE.match(line.strip()):
                reference_start = index
                break
        if reference_start is not None:
            for index in range(reference_start, len(lines)):
                masks[index].append((0, len(lines[index])))

    if "footnotes" in ignore:
        for index, line in enumerate(lines):
            if _FOOTNOTE_DEF_RE.match(line.strip()):
                masks[index].append((0, len(lines[index])))

    return [_merge_ranges(line_masks) for line_masks in masks]


def _covered(span: tuple[int, int], ranges: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < range_end and end > range_start for range_start, range_end in ranges)


def _term_pattern(term: str) -> re.Pattern[str]:
    escaped = re.escape(term)
    if any("\u4e00" <= char <= "\u9fff" for char in term):
        return re.compile(escaped)
    return re.compile(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", re.IGNORECASE)


def _bucket_for_rule(rule: dict[str, Any], profile: str, profile_config: dict[str, Any]) -> str:
    severity = rule.get("severity", "warning")
    if severity == "review":
        return "review_items"
    return _SEVERITY_BUCKETS.get(severity, "warnings")


def _is_approval_blocker(
    rule: dict[str, Any], profile: str, profile_config: dict[str, Any]
) -> bool:
    return (
        rule.get("severity") == "error"
        and profile in rule.get("blocker_profiles", [])
        and bool(profile_config.get("blocker_bucket"))
    )


def _findings_for_forbidden(
    rule: dict[str, Any],
    profile: str,
    profile_config: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
    extra_terms: list[str] | None = None,
) -> list[AuditFinding]:
    terms = list(rule.get("terms", []))
    terms.extend(extra_terms or [])
    findings: list[AuditFinding] = []
    allowlist = set(rule.get("allowlist", []))
    bucket = _bucket_for_rule(rule, profile, profile_config)
    severity = rule.get("severity", "warning")
    for term in terms:
        pattern = _term_pattern(term)
        for index, line in enumerate(text.splitlines(), start=1):
            for match in pattern.finditer(line):
                if _covered(match.span(), masks[index - 1]):
                    continue
                if match.group(0) in allowlist:
                    continue
                findings.append(
                    AuditFinding(
                        rule_id=rule["id"],
                        severity=severity,
                        bucket=bucket,
                        line=index,
                        message=rule["message"],
                        snippet=line.strip()[:200],
                    )
                )
    return findings


def _findings_for_regex(
    rule: dict[str, Any],
    profile: str,
    profile_config: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    try:
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
    except re.error as exc:
        raise PolicyError(f"rule {rule['id']} has an invalid pattern") from exc
    findings: list[AuditFinding] = []
    allowlist = set(rule.get("allowlist", []))
    bucket = _bucket_for_rule(rule, profile, profile_config)
    severity = rule.get("severity", "warning")
    for index, line in enumerate(text.splitlines(), start=1):
        for match in pattern.finditer(line):
            if _covered(match.span(), masks[index - 1]):
                continue
            if match.group(0) in allowlist:
                continue
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity=severity,
                    bucket=bucket,
                    line=index,
                    message=rule["message"],
                    snippet=line.strip()[:200],
                )
            )
    return findings


def _findings_for_budget(
    rule: dict[str, Any],
    profile_config: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    budget = profile_config.get("budget") or {}
    max_chars = budget.get("max_chars", 0)
    min_chars = budget.get("min_chars", 0)
    if max_chars == 0:
        return []
    scanned = 0
    for line, line_masks in zip(text.splitlines(), masks):
        ignored = sum(end - start for start, end in line_masks)
        scanned += max(0, len(line) - ignored)
    findings: list[AuditFinding] = []
    if max_chars and scanned > max_chars:
        findings.append(
            AuditFinding(
                rule_id=rule["id"],
                severity="warning",
                bucket="warnings",
                line=None,
                message=f"{rule['message']}: {scanned} > {max_chars}",
            )
        )
    if min_chars and scanned < min_chars:
        findings.append(
            AuditFinding(
                rule_id=rule["id"],
                severity="warning",
                bucket="warnings",
                line=None,
                message=f"{rule['message']}: {scanned} < {min_chars}",
            )
        )
    return findings


def _headings(text: str) -> list[tuple[int, int, str]]:
    result: list[tuple[int, int, str]] = []
    for index, line in enumerate(text.splitlines(), start=1):
        match = _HEADING_RE.match(line)
        if match:
            result.append((len(match.group(1)), index, match.group(2).strip()))
    return result


def _footnote_definition_lines(
    text: str,
    masks: list[list[tuple[int, int]]] | None = None,
) -> dict[str, list[int]]:
    definitions: dict[str, list[int]] = {}
    for index, line in enumerate(text.splitlines(), start=1):
        match = _FOOTNOTE_DEF_RE.match(line.strip())
        if not match:
            continue
        if masks is not None and _covered((0, len(line)), masks[index - 1]):
            continue
        label = match.group(1).strip()
        definitions.setdefault(label, []).append(index)
    return definitions


def _footnote_reference_lines(
    text: str,
    masks: list[list[tuple[int, int]]] | None = None,
) -> dict[str, list[int]]:
    references: dict[str, list[int]] = {}
    for index, line in enumerate(text.splitlines(), start=1):
        if masks is not None and _covered((0, len(line)), masks[index - 1]):
            continue
        for match in _FOOTNOTE_REF_RE.finditer(line):
            label = match.group(1).strip()
            references.setdefault(label, []).append(index)
    return references


def _footnote_reference_labels(
    text: str,
    masks: list[list[tuple[int, int]]] | None = None,
) -> set[str]:
    return set(_footnote_reference_lines(text, masks))


def _reference_heading_line(text: str, masks: list[list[tuple[int, int]]] | None = None) -> int | None:
    for index, line in enumerate(text.splitlines(), start=1):
        if not _REFERENCE_HEADING_RE.match(line.strip()):
            continue
        if masks is not None and _covered((0, len(line)), masks[index - 1]):
            continue
        return index
    return None


def _bibliography_item_count(text: str, masks: list[list[tuple[int, int]]] | None = None) -> int:
    heading_line = _reference_heading_line(text, masks)
    if heading_line is None:
        return 0
    lines = text.splitlines()
    headings = _headings(text)
    heading_level: int | None = None
    end_line = len(lines) + 1
    for level, line_no, _ in headings:
        if line_no == heading_line:
            heading_level = level
        elif heading_level is not None and line_no > heading_line and level <= heading_level:
            end_line = line_no
            break
    count = 0
    for index in range(heading_line, end_line - 1):
        line = lines[index]
        if masks is not None and _covered((0, len(line)), masks[index]):
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        count += 1
    return count


def _section_body_text(text: str, pattern: str) -> str:
    headings = _headings(text)
    pattern_re = re.compile(pattern, re.IGNORECASE)
    lines = text.splitlines()
    for index, (level, line_no, heading) in enumerate(headings):
        if not pattern_re.search(heading):
            continue
        end_line = len(lines) + 1
        for later_level, later_line, _ in headings[index + 1:]:
            if later_level <= level:
                end_line = later_line
                break
        return "\n".join(lines[line_no:end_line - 1])
    return ""


def _findings_for_required_section_content(
    profile_config: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    lines = text.splitlines()
    headings = _headings(text)
    for required in profile_config.get("required_sections", []):
        pattern = re.compile(required["pattern"], re.IGNORECASE)
        match_index = next(
            (
                index
                for index, (_, _, heading) in enumerate(headings)
                if pattern.search(heading)
            ),
            None,
        )
        if match_index is None:
            continue
        level, start_line, heading = headings[match_index]
        end_line = len(lines) + 1
        for later_level, later_line, _ in headings[match_index + 1:]:
            if later_level <= level:
                end_line = later_line
                break
        visible: list[str] = []
        for line_index in range(start_line + 1, end_line):
            line = lines[line_index - 1]
            if masks and _covered((0, len(line)), masks[line_index - 1]):
                continue
            visible.append(line)
        min_chars = int(required.get("min_non_whitespace_chars", 0) or 0)
        if min_chars:
            non_ws = sum(len(line.strip()) for line in visible)
            if non_ws < min_chars:
                severity = required.get("under_min_severity", "error")
                findings.append(
                    AuditFinding(
                        rule_id="required_section_content",
                        severity=severity,
                        bucket=_SEVERITY_BUCKETS.get(severity, "errors"),
                        line=start_line,
                        message=f"必备部分为空或内容不足: {heading}",
                        snippet=heading[:200],
                    )
                )
        min_items = int(required.get("min_items", 0) or 0)
        if min_items:
            item_count = sum(1 for line in visible if line.strip())
            if item_count < min_items:
                severity = required.get("under_min_severity", "error")
                findings.append(
                    AuditFinding(
                        rule_id="required_section_content",
                        severity=severity,
                        bucket=_SEVERITY_BUCKETS.get(severity, "errors"),
                        line=start_line,
                        message=f"必备部分条目不足: {heading}",
                        snippet=heading[:200],
                    )
                )
    return findings


def _findings_for_footnote_integrity(
    rule: dict[str, Any],
    profile_config: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    config = profile_config.get("footnotes") or {}
    if not config.get("enabled", False):
        return []
    definitions = _footnote_definition_lines(text, masks)
    references = _footnote_reference_lines(text, masks)
    findings: list[AuditFinding] = []
    for label in sorted(set(references) - set(definitions)):
        severity = config.get("missing_severity", "error")
        findings.append(
            AuditFinding(
                rule_id=rule["id"],
                severity=severity,
                bucket=_SEVERITY_BUCKETS.get(severity, "errors"),
                line=references[label][0],
                message=f"{rule['message']}: 引用 [^{label}] 缺少定义",
                snippet=label,
            )
        )
    for label, definition_lines in definitions.items():
        if len(definition_lines) <= 1:
            continue
        severity = config.get("duplicate_severity", "error")
        findings.append(
            AuditFinding(
                rule_id=rule["id"],
                severity=severity,
                bucket=_SEVERITY_BUCKETS.get(severity, "errors"),
                line=definition_lines[1],
                message=f"{rule['message']}: 定义 [^{label}] 重复",
                snippet=label,
            )
        )
    for label in sorted(set(definitions) - set(references)):
        severity = config.get("orphan_severity", "warning")
        findings.append(
            AuditFinding(
                rule_id=rule["id"],
                severity=severity,
                bucket=_SEVERITY_BUCKETS.get(severity, "warnings"),
                line=definitions[label][0],
                message=f"{rule['message']}: 定义 [^{label}] 未被引用",
                snippet=label,
            )
        )
    return findings


def _findings_for_bibliography(
    rule: dict[str, Any],
    profile_config: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    config = profile_config.get("bibliography") or {}
    if not config.get("enabled", False):
        return []
    min_items = int(config.get("min_items", 0) or 0)
    count = _bibliography_item_count(text, masks)
    if not min_items or count >= min_items:
        return []
    severity = config.get("empty_severity", "error")
    return [
        AuditFinding(
            rule_id=rule["id"],
            severity=severity,
            bucket=_SEVERITY_BUCKETS.get(severity, "errors"),
            line=_reference_heading_line(text, masks),
            message=f"{rule['message']}: {count} < {min_items}",
            snippet="参考文献",
        )
    ]


def _bibliography_items(text: str, masks: list[list[tuple[int, int]]]) -> list[tuple[int, str]]:
    heading_line = _reference_heading_line(text, masks)
    if heading_line is None:
        return []
    lines = text.splitlines()
    headings = _headings(text)
    heading_level: int | None = None
    end_line = len(lines) + 1
    for level, line_no, _ in headings:
        if line_no == heading_line:
            heading_level = level
        elif heading_level is not None and line_no > heading_line and level <= heading_level:
            end_line = line_no
            break
    items: list[tuple[int, str]] = []
    for index in range(heading_line, end_line - 1):
        line = lines[index]
        if masks is not None and _covered((0, len(line)), masks[index]):
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        items.append((index + 1, stripped))
    return items


def _bibliography_entry_fields(item: str) -> tuple[str, set[str]]:
    entry_type = "book"
    fields: set[str] = set()
    if re.search(r"(期刊|杂志|学报|季刊|第.{1,8}期|\d+卷|卷\s*\d+)", item):
        entry_type = "article"
        fields.add("journal")
    if re.search(r"(收录于|载于|收入|见),?\s*《", item) or re.search(r"第.{1,10}章", item):
        entry_type = "chapter"
        fields.add("container_title")
    if re.search(r"([一二三四五六七八九十百0-9]{1,4}版|出版社|书局|书店|University Press|Verlag|Press)", item):
        fields.add("publisher")
    if re.search(r"(19|20)\d{2}", item):
        fields.add("year")
    author_match = re.match(r"^\s*\d+[\.、]\s*(.+?)[：:(（]?《", item)
    if author_match:
        fields.add("author")
    elif re.match(r"^\s*[^《]{1,24}[：:]\s*《", item):
        fields.add("author")
    if "《" in item:
        fields.add("title")
    return entry_type, fields


def _findings_for_bibliography_completeness(
    rule: dict[str, Any],
    profile_config: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    config = profile_config.get("bibliography_completeness") or {}
    if not config.get("enabled", False):
        return []
    required_by_type = config.get("required_fields_by_type") or {}
    severity = config.get("severity", "review")
    bucket = _SEVERITY_BUCKETS.get(severity, "review_items")
    findings: list[AuditFinding] = []
    for line_no, item in _bibliography_items(text, masks):
        entry_type, fields = _bibliography_entry_fields(item)
        required = required_by_type.get(entry_type, [])
        missing = [field for field in required if field not in fields]
        if not missing:
            continue
        findings.append(
            AuditFinding(
                rule_id=rule["id"],
                severity=severity,
                bucket=bucket,
                line=line_no,
                message=(
                    f"{rule['message']}（{entry_type}）: "
                    + ", ".join(missing)
                ),
                snippet=item[:200],
            )
        )
    return findings


def _findings_for_citation_surface(
    rule: dict[str, Any],
    profile_config: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    config = profile_config.get("citation_surface") or {}
    if not config.get("enabled", False):
        return []
    researchers = config.get("researchers", [])
    if not researchers:
        return []
    lines = text.splitlines()
    body_parts: list[str] = []
    for index, line in enumerate(lines, start=1):
        if masks and _covered((0, len(line)), masks[index - 1]):
            continue
        body_parts.append(line)
    body_text = "\n".join(body_parts)
    reference_line = _reference_heading_line(text, masks)
    reference_text = ""
    if reference_line is not None:
        reference_text = "\n".join(lines[reference_line:])
    findings: list[AuditFinding] = []
    for entry in researchers:
        name = entry.get("name", "")
        variants = [variant for variant in [name, *entry.get("variants", [])] if variant]
        bibliography_terms = [
            term for term in entry.get("bibliography_terms", []) if term
        ]
        if variants and not any(variant in body_text for variant in variants):
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity=rule.get("severity", "review"),
                    bucket="review_items",
                    line=None,
                    message=f"{rule['message']}: {name}",
                    snippet=name[:200],
                )
            )
        if bibliography_terms and not any(
            term in reference_text for term in bibliography_terms
        ):
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity=rule.get("severity", "review"),
                    bucket="review_items",
                    line=None,
                    message=f"参考文献未覆盖研究者: {name}",
                    snippet=name[:200],
                )
            )
    return findings


def detect_line_endings(raw: bytes) -> dict[str, Any]:
    """Report the dominant and mixed-state line endings of raw bytes."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("detect_line_endings requires bytes")
    data = bytes(raw)
    crlf = data.count(b"\r\n")
    lf = data.count(b"\n") - crlf
    cr = data.count(b"\r") - crlf
    styles: list[str] = []
    if lf:
        styles.append("lf")
    if crlf:
        styles.append("crlf")
    if cr:
        styles.append("cr")
    if not styles:
        return {"mixed": False, "dominant": None, "styles": []}
    return {
        "mixed": len(styles) > 1,
        "dominant": styles[0],
        "styles": styles,
    }


def normalize_line_endings(text: str, line_ending: str) -> str:
    if line_ending not in _LINE_ENDING_NAMES:
        raise ValueError(f"unsupported line ending {line_ending!r}")
    sep = _LINE_ENDING_NAMES[line_ending]
    if text.endswith("\n") or text.endswith("\r"):
        return sep.join(text.splitlines()) + sep
    return sep.join(text.splitlines())


def line_ending_report(
    raw: bytes,
    policy_snapshot: dict[str, Any] | None = None,
    configured_default: str | None = None,
) -> dict[str, Any]:
    detected = detect_line_endings(raw)
    if configured_default is None and isinstance(policy_snapshot, dict):
        configured_default = (policy_snapshot.get("line_endings") or {}).get("default")
    if configured_default not in _LINE_ENDING_NAMES:
        configured_default = "lf"
    severity = "ok"
    message: str | None = None
    if detected["mixed"]:
        severity = (policy_snapshot.get("line_endings") or {}).get("mixed_severity") or "error"
        message = "MIXED_LINE_ENDINGS"
    elif detected["dominant"] not in (None, configured_default):
        severity = (policy_snapshot.get("line_endings") or {}).get("mismatch_severity") or "warning"
        message = "LINE_ENDINGS_MISMATCH"
    return {
        "detected": detected["dominant"],
        "mixed": detected["mixed"],
        "styles": detected["styles"],
        "configured_default": configured_default,
        "severity": severity,
        "message": message,
    }


def build_public_draft(
    text: str,
    policy_snapshot: dict[str, Any] | None = None,
    line_ending: str = "lf",
) -> tuple[str, dict[str, Any]]:
    annotations, cleaned = extract_writing_annotations(text)
    normalized: list[str] = []
    blank_run = 0
    collapsed = 0
    for line in cleaned.splitlines():
        if not line.strip():
            blank_run += 1
            if blank_run > 2:
                collapsed += 1
                continue
            normalized.append("")
        else:
            blank_run = 0
            normalized.append(line.rstrip())
    public_text = normalize_line_endings("\n".join(normalized), line_ending)
    report: dict[str, Any] = {
        "removed_nodes": len(annotations),
        "normalized_whitespace": collapsed > 0,
        "collapsed_blank_lines": collapsed,
        "line_ending": line_ending,
        "line_ending_normalized": line_ending != "lf",
    }
    return public_text, report


def _normalized_heading(heading: str) -> str:
    return re.sub(r"\s+", " ", heading.strip()).lower()


def _heading_signature(text: str) -> list[tuple[int, str]]:
    return [
        (level, _normalized_heading(heading))
        for level, _, heading in _headings(text)
        if level <= 3
    ]


def _count_tables(text: str) -> int:
    count = 0
    in_table = False
    for line in text.splitlines():
        stripped = line.strip()
        is_row = stripped.startswith("|")
        if is_row and not in_table:
            count += 1
            in_table = True
        elif not is_row:
            in_table = False
    return count


def _count_direct_quotes(text: str) -> int:
    return len(re.findall(r"[“”]", text))


def check_public_parity(
    source_text: str,
    public_text: str,
    policy_snapshot: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    source_text = strip_writing_annotations(source_text)
    source_text = normalize_line_endings(source_text, "lf")
    public_text = normalize_line_endings(public_text, "lf")
    problems: list[str] = []
    if _heading_signature(source_text) != _heading_signature(public_text):
        problems.append("public 导出的标题集合或顺序发生变化")
    source_abstract = _section_body_text(source_text, r"^(摘要|Abstract)$")
    public_abstract = _section_body_text(public_text, r"^(摘要|Abstract)$")
    if bool(source_abstract.strip()) != bool(public_abstract.strip()):
        problems.append("public 导出的摘要非空性发生变化")
    if _footnote_reference_labels(source_text) != _footnote_reference_labels(public_text):
        problems.append("public 导出的脚注引用标签集合发生变化")
    if set(_footnote_definition_lines(source_text)) != set(
        _footnote_definition_lines(public_text)
    ):
        problems.append("public 导出的脚注定义标签集合发生变化")
    if _count_tables(source_text) != _count_tables(public_text):
        problems.append("public 导出的表格数量发生变化")
    if _count_direct_quotes(source_text) != _count_direct_quotes(public_text):
        problems.append("public 导出的直接引语数量发生变化")
    if _bibliography_item_count(source_text) != _bibliography_item_count(public_text):
        problems.append("public 导出的参考文献条目数发生变化")
    return (not problems), problems



def _findings_for_required_sections(
    profile_config: dict[str, Any],
    text: str,
) -> list[AuditFinding]:
    headings = [heading.lower() for _, _, heading in _headings(text)]
    findings: list[AuditFinding] = []
    for required in profile_config.get("required_sections", []):
        pattern = re.compile(required["pattern"], re.IGNORECASE)
        if any(pattern.search(heading) for heading in headings):
            continue
        bucket = required.get("bucket", "review_items")
        findings.append(
            AuditFinding(
                rule_id="required_sections",
                severity=_BUCKET_SEVERITY.get(bucket, "review"),
                bucket=bucket,
                line=None,
                message=required["message"],
            )
        )
    return findings


def _cn_number(value: str) -> int:
    total = 0
    section = 0
    for char in value:
        digit = _CN_DIGITS.get(char)
        if digit is None:
            continue
        if digit == 100:
            total += max(section, 1) * 100
            section = 0
        elif digit == 10:
            total += max(section, 1) * 10
            section = 0
        else:
            section = digit
    return total + section


def _findings_for_section_numbering(
    rule: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    chapter_number: int | None = None
    last_number: int | None = None
    seen: set[int] = set()
    for level, line_no, heading in _headings(text):
        chapter_match = _CHAPTER_CN_RE.search(heading)
        if chapter_match:
            chapter_number = _cn_number(chapter_match.group(1))
            last_number = None
            seen = set()
            continue
        en_match = _CHAPTER_EN_RE.match(heading)
        if en_match:
            chapter_number = int(en_match.group(1))
            last_number = None
            seen = set()
            continue
        number_match = _NUMERIC_SECTION_RE.match(heading) or _CN_SECTION_RE.match(heading)
        if not number_match:
            continue
        raw = number_match.group(1)
        number = int(raw) if raw.isdigit() else _cn_number(raw)
        if number in seen:
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity=rule.get("severity", "warning"),
                    bucket=_SEVERITY_BUCKETS.get(rule.get("severity", "warning"), "warnings"),
                    line=line_no,
                    message=f"{rule['message']}: duplicate section number {raw!r}",
                    snippet=heading[:200],
                )
            )
        if last_number is not None and number < last_number:
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity=rule.get("severity", "warning"),
                    bucket=_SEVERITY_BUCKETS.get(rule.get("severity", "warning"), "warnings"),
                    line=line_no,
                    message=f"{rule['message']}: {raw!r} follows {last_number!r}",
                    snippet=heading[:200],
                )
            )
        seen.add(number)
        last_number = number
    return findings


def _parse_writing_comment(body: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("- "):
            if current_key is not None:
                result.setdefault(current_key, [])
                if isinstance(result[current_key], list):
                    result[current_key].append(line[2:].strip())
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        current_key = key
        if not value:
            result[key] = []
            continue
        try:
            result[key] = json.loads(value)
        except json.JSONDecodeError:
            result[key] = value
    return result


def extract_writing_annotations(text: str) -> tuple[list[dict[str, Any]], str]:
    annotations: list[dict[str, Any]] = []
    cleaned = text
    for match in _WRITING_COMMENT_RE.finditer(text):
        body = match.group(0)[4:-3]
        if "writing:" in body:
            body = body.split("writing:", 1)[1]
        parsed = _parse_writing_comment(body)
        if parsed:
            annotations.append(parsed)
    cleaned = _WRITING_COMMENT_RE.sub(lambda match: "\n" * match.group(0).count("\n"), text)
    return annotations, cleaned


def strip_writing_annotations(text: str) -> str:
    _, cleaned = extract_writing_annotations(text)
    return cleaned


def _normalize_sidecar(sidecar: dict[str, Any] | list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if sidecar is None:
        return []
    if isinstance(sidecar, dict):
        if "section_id" in sidecar or "argument_gain" in sidecar:
            return [sidecar]
        records: list[dict[str, Any]] = []
        for section_id, value in sidecar.items():
            if isinstance(value, dict):
                record = dict(value)
                record.setdefault("section_id", section_id)
                records.append(record)
            else:
                records.append({"section_id": section_id, "argument_gain": value})
        return records
    if isinstance(sidecar, list):
        return [record for record in sidecar if isinstance(record, dict)]
    raise PolicyError("sidecar annotations must be an object or a list of objects")


def _findings_for_argument_gain(
    rule: dict[str, Any],
    profile_config: dict[str, Any],
    text: str,
    annotations: list[dict[str, Any]],
    managed_draft: bool,
) -> list[AuditFinding]:
    if not managed_draft and not annotations:
        return []
    section_records = [record for record in annotations if record.get("section_id")]
    findings: list[AuditFinding] = []
    allowed = {"new_evidence", "new_inference", "concept_distinction",
               "rival_interpretation", "revision", "unresolved_mechanism"}
    for level, line_no, heading in _headings(text):
        if level < 2:
            continue
        record = next(
            (
                item
                for item in section_records
                if item.get("section_id") == heading
                or item.get("section_id") == heading.lower()
            ),
            None,
        )
        gains = record.get("argument_gain") if record else None
        if record and record.get("not_applicable") is True:
            continue
        if not isinstance(gains, list) or not gains:
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity=rule.get("severity", "warning"),
                    bucket=_SEVERITY_BUCKETS.get(rule.get("severity", "warning"), "warnings"),
                    line=line_no,
                    message=f"{rule['message']}: {heading!r}",
                    snippet=heading[:200],
                )
            )
            continue
        invalid = [gain for gain in gains if gain not in allowed]
        if invalid:
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity="warning",
                    bucket="warnings",
                    line=line_no,
                    message=f"argument_gain contains unknown gain values: {', '.join(invalid)}",
                    snippet=heading[:200],
                )
            )
    return findings


def _findings_for_compression_duplicates(
    rule: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
) -> list[AuditFinding]:
    counts: dict[str, list[int]] = {}
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if len(stripped) < 12 or stripped.startswith("#"):
            continue
        if _covered((0, len(line)), masks[index - 1]):
            continue
        counts.setdefault(stripped, []).append(index)
    findings: list[AuditFinding] = []
    for stripped, line_numbers in sorted(counts.items()):
        if len(line_numbers) >= 3:
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity=rule.get("severity", "review"),
                    bucket="review_items",
                    line=line_numbers[0],
                    message=f"{rule['message']}: {len(line_numbers)} 处相同表述",
                    snippet=stripped[:200],
                )
            )
    return findings[:20]


def _findings_for_compression_limits(
    rule: dict[str, Any],
    text: str,
    masks: list[list[tuple[int, int]]],
    snapshot: dict[str, Any],
) -> list[AuditFinding]:
    terms = snapshot.get("compression_review", {}).get("limit_echo_terms", [])
    findings: list[AuditFinding] = []
    for term in terms:
        pattern = _term_pattern(term)
        line_numbers: list[int] = []
        for index, line in enumerate(text.splitlines(), start=1):
            for match in pattern.finditer(line):
                if not _covered(match.span(), masks[index - 1]):
                    line_numbers.append(index)
        if len(line_numbers) >= 2:
            findings.append(
                AuditFinding(
                    rule_id=rule["id"],
                    severity=rule.get("severity", "review"),
                    bucket="review_items",
                    line=line_numbers[0],
                    message=f"{rule['message']}: {term!r} 出现 {len(line_numbers)} 次",
                    snippet=term,
                )
            )
    return findings


def _findings_for_research_history_repeat(text: str) -> list[AuditFinding]:
    chapters: dict[int, str] = {}
    current: int | None = None
    for level, _, heading in _headings(text):
        if level == 1 and ("章" in heading or heading.startswith("Chapter")):
            current = len(chapters)
            chapters[current] = ""
        elif current is not None:
            chapters[current] += heading + "\n"
    sentences: dict[str, set[int]] = {}
    for chapter_id, body in chapters.items():
        for sentence in re.split(r"[。！？；\n]", body):
            cleaned = sentence.strip()
            if len(cleaned) >= 20:
                sentences.setdefault(cleaned, set()).add(chapter_id)
    findings: list[AuditFinding] = []
    for sentence, chapter_ids in sorted(sentences.items()):
        if len(chapter_ids) >= 2:
            findings.append(
                AuditFinding(
                    rule_id="compression_review_research_history",
                    severity="review",
                    bucket="review_items",
                    line=None,
                    message=f"同一研究史表述出现在 {len(chapter_ids)} 个章节",
                    snippet=sentence[:200],
                )
            )
    return findings[:10]


def _findings_for_conclusion_status(
    text: str,
    profile_config: dict[str, Any],
) -> list[AuditFinding]:
    headings = _headings(text)
    conclusion_index: int | None = None
    for index, (level, _, heading) in enumerate(headings):
        if re.match(r"^结论$", heading):
            conclusion_index = index
            break
    if conclusion_index is None:
        return []
    start_line = headings[conclusion_index][1]
    end_line = len(text.splitlines())
    for later_level, later_line, _ in headings[conclusion_index + 1:]:
        if later_level <= headings[conclusion_index][0]:
            end_line = later_line - 1
            break
    body = "\n".join(text.splitlines()[start_line - 1:end_line])
    findings: list[AuditFinding] = []
    status_terms = ["REVIEW", "APPROVED", "PENDING_PAGE", "审批", "本轮核验", "等待人工"]
    for term in status_terms:
        if _term_pattern(term).search(body):
            findings.append(
                AuditFinding(
                    rule_id="compression_review_conclusion_status",
                    severity="error",
                    bucket="errors",
                    line=start_line,
                    message=f"结论部分包含项目状态或流程信息：{term}",
                    snippet=term,
                )
            )
    return findings


def _run_rules(
    text: str,
    *,
    policy_snapshot: dict[str, Any],
    profile: str,
    profile_config: dict[str, Any],
    annotations: list[dict[str, Any]],
    managed_draft: bool,
    mode: str,
) -> tuple[list[AuditFinding], int, int]:
    _, cleaned = extract_writing_annotations(text)
    findings: list[AuditFinding] = []
    for rule in policy_snapshot.get("rules", []):
        ignore = set(rule.get("ignore", []))
        masks = _line_masks(cleaned, ignore)
        kind = rule.get("kind")
        if kind == "forbidden_term":
            findings.extend(
                _findings_for_forbidden(
                    rule,
                    profile,
                    profile_config,
                    cleaned,
                    masks,
                    policy_snapshot.get("extra_forbidden_terms", []),
                )
            )
        elif kind == "regex":
            findings.extend(_findings_for_regex(rule, profile, profile_config, cleaned, masks))
        elif kind == "budget":
            findings.extend(_findings_for_budget(rule, profile_config, cleaned, masks))
        elif kind == "section_numbering":
            findings.extend(_findings_for_section_numbering(rule, cleaned, masks))
        elif kind == "required_section":
            findings.extend(_findings_for_required_sections(profile_config, cleaned))
        elif kind == "required_section_content":
            findings.extend(_findings_for_required_section_content(profile_config, cleaned, masks))
        elif kind == "footnote_integrity":
            findings.extend(_findings_for_footnote_integrity(rule, profile_config, cleaned, masks))
        elif kind == "bibliography":
            findings.extend(_findings_for_bibliography(rule, profile_config, cleaned, masks))
        elif kind == "bibliography_completeness":
            findings.extend(
                _findings_for_bibliography_completeness(
                    rule, profile_config, cleaned, masks
                )
            )
        elif kind == "citation_surface":
            findings.extend(_findings_for_citation_surface(rule, profile_config, cleaned, masks))
        elif kind == "argument_gain":
            findings.extend(
                _findings_for_argument_gain(
                    rule, profile_config, cleaned, annotations, managed_draft
                )
            )
        elif kind == "compression_duplicate":
            findings.extend(_findings_for_compression_duplicates(rule, cleaned, masks))
        elif kind == "compression_limit_echo":
            findings.extend(
                _findings_for_compression_limits(rule, cleaned, masks, policy_snapshot)
            )

    if mode == "compression_review":
        findings.extend(_findings_for_research_history_repeat(cleaned))
        findings.extend(_findings_for_conclusion_status(cleaned, profile_config))

    blocker_ids = {
        rule["id"]
        for rule in policy_snapshot.get("rules", [])
        if _is_approval_blocker(rule, profile, profile_config)
    }
    if profile_config.get("blocker_bucket"):
        blocker_ids.add("compression_review_conclusion_status")
    expanded: list[AuditFinding] = []
    for finding in findings:
        expanded.append(finding)
        if finding.bucket == "errors" and finding.rule_id in blocker_ids:
            expanded.append(
                AuditFinding(
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    bucket="approval_blockers",
                    line=finding.line,
                    message=finding.message,
                    snippet=finding.snippet,
                )
            )
    findings = expanded

    scanned = 0
    ignored = 0
    all_masks = _line_masks(cleaned, {"code_blocks", "inline_code", "html_comments", "front_matter"})
    for line, line_masks in zip(cleaned.splitlines(), all_masks):
        ignored += sum(end - start for start, end in line_masks)
        scanned += max(0, len(line) - sum(end - start for start, end in line_masks))
    return findings, scanned, ignored


def audit_document(
    text: str,
    *,
    policy: dict[str, Any] | None = None,
    policy_snapshot: dict[str, Any] | None = None,
    profile: str | None = None,
    source_path: str | Path | None = None,
    managed_draft: bool | None = None,
    sidecar_annotations: dict[str, Any] | list[dict[str, Any]] | None = None,
    project_config: dict[str, Any] | None = None,
    manifest_overrides: dict[str, Any] | None = None,
    mode: str = "full",
) -> AuditResult:
    base = policy if policy is not None else load_writing_policy()
    profile_name = profile or base["default_profile"]
    if profile_name not in KNOWN_PROFILES:
        raise PolicyError(f"unknown writing policy profile {profile_name!r}")
    if policy_snapshot is not None:
        validate_resolved_policy(policy_snapshot)
        if policy_snapshot.get("profile") != profile_name:
            raise PolicyError(
                f"policy snapshot profile {policy_snapshot.get('profile')!r} does not match {profile_name!r}"
            )
        if policy_snapshot.get("policy_version") != base.get("policy_version"):
            raise PolicyError("policy snapshot version does not match the loaded policy")
        snapshot = policy_snapshot
    else:
        snapshot = resolve_writing_policy(
            base,
            profile=profile_name,
            project_config=project_config,
            manifest_overrides=manifest_overrides,
        )
    profile_config = snapshot
    is_managed = (
        bool(profile_config.get("managed_annotation_required"))
        if managed_draft is None
        else managed_draft
    )
    comment_annotations, _ = extract_writing_annotations(text)
    annotations = comment_annotations + _normalize_sidecar(sidecar_annotations)
    findings, scanned, ignored = _run_rules(
        text,
        policy_snapshot=snapshot,
        profile=profile_name,
        profile_config=profile_config,
        annotations=annotations,
        managed_draft=is_managed,
        mode=mode,
    )
    return AuditResult(
        profile=profile_name,
        policy_version=snapshot.get("policy_version", ""),
        policy_fingerprint=policy_fingerprint(snapshot),
        policy_snapshot=snapshot,
        findings=tuple(findings),
        scanned_chars=scanned,
        ignored_chars=ignored,
        annotations=tuple(annotations),
        managed_draft=is_managed,
        mode=mode,
        source_path=str(source_path) if source_path else None,
    )


def run_compression_review(
    text: str,
    *,
    policy: dict[str, Any] | None = None,
    policy_snapshot: dict[str, Any] | None = None,
    profile: str | None = None,
    source_path: str | Path | None = None,
    sidecar_annotations: dict[str, Any] | list[dict[str, Any]] | None = None,
    project_config: dict[str, Any] | None = None,
    manifest_overrides: dict[str, Any] | None = None,
) -> AuditResult:
    return audit_document(
        text,
        policy=policy,
        policy_snapshot=policy_snapshot,
        profile=profile,
        source_path=source_path,
        sidecar_annotations=sidecar_annotations,
        project_config=project_config,
        manifest_overrides=manifest_overrides,
        mode="compression_review",
    )


def _cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the research-kb writing policy audit")
    parser.add_argument("input", help="Markdown file to audit")
    parser.add_argument("--profile", choices=KNOWN_PROFILES, default=None)
    parser.add_argument(
        "--compression-review",
        action="store_true",
        help="run the additional compression review checks",
    )
    managed = parser.add_mutually_exclusive_group()
    managed.add_argument(
        "--managed-draft",
        action="store_true",
        help="require argument_gain annotations on managed draft sections",
    )
    managed.add_argument(
        "--external-draft",
        action="store_true",
        help="treat the input as an external draft without annotation requirements",
    )
    parser.add_argument(
        "--sidecar",
        default=None,
        help="JSON sidecar file mapping section_id to argument_gain annotations",
    )
    parser.add_argument("--check", action="store_true", help="emit the audit result as JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit with status 1 when errors or approval blockers are present",
    )
    parser.add_argument(
        "--export",
        default=None,
        metavar="OUT",
        help="write annotation-stripped markdown to OUT",
    )
    parser.add_argument(
        "--export-build-report",
        default=None,
        metavar="OUT",
        help="write the public export build and parity report JSON to OUT",
    )
    parser.add_argument(
        "--line-ending",
        choices=("lf", "crlf"),
        default=None,
        help="line ending for exported drafts (default: policy line_endings.default)",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        metavar="OUT",
        help="write the audit result JSON to OUT",
    )
    parser.add_argument(
        "--policy",
        default=None,
        metavar="JSON",
        help="path to a writing policy JSON file",
    )
    parser.add_argument(
        "--project-config",
        default=None,
        metavar="JSON",
        help="path to a project config JSON object",
    )
    snapshot_group = parser.add_mutually_exclusive_group()
    snapshot_group.add_argument(
        "--policy-snapshot",
        default=None,
        metavar="JSON",
        help="path to a pre-resolved policy snapshot JSON",
    )
    snapshot_group.add_argument(
        "--policy-overrides",
        default=None,
        metavar="JSON",
        help="path to report manifest writing policy overrides JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _cli_parser().parse_args(argv)
    sidecar: dict[str, Any] | list[dict[str, Any]] | None = None
    if args.sidecar:
        sidecar = json.loads(Path(args.sidecar).read_text(encoding="utf-8"))
    raw_source = Path(args.input).read_bytes()
    text = raw_source.decode("utf-8")
    managed_draft: bool | None
    if args.managed_draft:
        managed_draft = True
    elif args.external_draft:
        managed_draft = False
    else:
        managed_draft = None
    policy: dict[str, Any] | None = None
    if args.policy:
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    project_config: dict[str, Any] | None = None
    if args.project_config:
        project_config = json.loads(Path(args.project_config).read_text(encoding="utf-8"))
    policy_snapshot: dict[str, Any] | None = None
    if args.policy_snapshot:
        policy_snapshot = json.loads(Path(args.policy_snapshot).read_text(encoding="utf-8"))
    manifest_overrides: dict[str, Any] | None = None
    if args.policy_overrides:
        manifest_overrides = json.loads(Path(args.policy_overrides).read_text(encoding="utf-8"))
    result = audit_document(
        text,
        policy=policy,
        policy_snapshot=policy_snapshot,
        profile=args.profile,
        source_path=args.input,
        managed_draft=managed_draft,
        sidecar_annotations=sidecar,
        project_config=project_config,
        manifest_overrides=manifest_overrides,
        mode="compression_review" if args.compression_review else "full",
    )
    data = result.as_dict()
    if args.export:
        configured = (result.policy_snapshot.get("line_endings") or {}).get("default")
        output_line_ending = getattr(args, "line_ending", None) or configured or "lf"
        public_text, build_report = build_public_draft(
            text,
            policy_snapshot=result.policy_snapshot,
            line_ending=output_line_ending,
        )
        build_report["line_ending_report"] = line_ending_report(
            raw_source, result.policy_snapshot, configured
        )
        parity_ok, parity_problems = check_public_parity(
            text, public_text, policy_snapshot=result.policy_snapshot
        )
        build_report["parity"] = {"ok": parity_ok, "problems": parity_problems}
        if args.export_build_report:
            Path(args.export_build_report).write_text(
                json.dumps(build_report, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        if not parity_ok:
            print(
                json.dumps(
                    {"export": False, "parity_problems": parity_problems},
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 1
        Path(args.export).write_text(public_text, encoding="utf-8")
    if args.manifest:
        Path(args.manifest).write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.check or (not args.export and not args.manifest):
        print(json.dumps(data, ensure_ascii=False, indent=2))
    if args.strict and (data["errors"] or data["approval_blockers"]):
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
