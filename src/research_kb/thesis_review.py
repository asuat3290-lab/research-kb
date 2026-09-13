# -*- coding: utf-8 -*-
"""thesis_review: lightweight review + controlled-revision audit for research-kb.

Independent optional capability. This module does NOT modify SQLite, the MCP
tool surface, Claim/Link/Event semantics, submit_research_report,
writing_policy.*, or delivery_package.py.

It validates machine-readable review artifacts:

- 00-review-summary.json   (findings grouped by severity)
- 01-argument-map.json     (claim/definition/inference nodes and relations)
- 08-revision-items.json   (revision tasks with human_status lifecycle)

and audits a review directory against the required file set. Revision items
are intended to be registered in research-kb as ``note`` items (status
``candidate``) and approved through the existing approval machinery; this
module deliberately does not add a new research_items kind.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

from ._resources import PackagedResourceError, read_json_resource, resource_traversable

POLICY_VERSION = "1.0.0"
SCHEMA_VERSION = "1"

STAGES = (
    "ingest",
    "argument_map",
    "evidence_audit",
    "semantic_review",
    "adversarial_review",
    "revision_plan",
    "controlled_revision",
    "post_revision_audit",
)

SEVERITIES = ("critical", "major", "moderate", "minor")
HUMAN_STATUSES = ("proposed", "approved", "rejected", "completed")
PROBLEM_TYPES = (
    "argument_gap",
    "circular_argument",
    "unsupported_premise",
    "overclaim",
    "evidence_mismatch",
    "quote_function_abuse",
    "concept_drift",
    "cross_chapter_conflict",
    "rival_unaddressed",
    "literature_gap",
    "other",
)
NODE_KINDS = (
    "thesis",
    "chapter_claim",
    "key_definition",
    "intermediate_inference",
    "rival_response",
    "dependency",
)
FINDING_CATEGORIES = (
    "argument",
    "evidence",
    "concept",
    "cross_chapter",
    "adversarial",
    "other",
)

# Human-readable markdown files that must exist in a review directory.
REQUIRED_REVIEW_MARKDOWN = (
    "00-review-summary.md",
    "01-argument-map.md",
    "02-evidence-audit.md",
    "03-concept-drift.md",
    "04-cross-chapter-conflicts.md",
    "05-adversarial-review.md",
    "06-overclaims.md",
    "07-literature-gaps.md",
    "08-revision-priorities.md",
    "revision-audit.md",
)

# Machine-readable artifacts (optional but recommended).
OPTIONAL_REVIEW_JSON = (
    "00-review-summary.json",
    "01-argument-map.json",
    "08-revision-items.json",
)

VERSION_SIDECAR = "versions.sha256"

DEFAULT_SCHEMA_RESOURCE = "thesis_review.schema.json"
DEFAULT_TEMPLATE_RESOURCE = ("templates", "thesis-review")


class ThesisReviewResourceError(RuntimeError):
    """A required thesis-review schema or template is unavailable."""


def load_review_schema() -> dict[str, object]:
    """Load the installed thesis-review schema without checkout-relative paths."""

    try:
        return read_json_resource(DEFAULT_SCHEMA_RESOURCE)
    except PackagedResourceError as exc:
        raise ThesisReviewResourceError("thesis-review schema resource is unavailable") from exc


def _s(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _unique(problems: list[tuple[str, str]], path: str, values: list[object]) -> None:
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        key = value.strip()
        if key in seen:
            problems.append((path, f"duplicate id {key!r}"))
        seen.add(key)


def validate_review_summary(doc: object) -> list[tuple[str, str]]:
    """Return [(path, problem)] for a review summary document."""
    problems: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("$", "review summary must be a JSON object")]
    if doc.get("schema_version") != SCHEMA_VERSION:
        problems.append(("schema_version", f"schema_version must be {SCHEMA_VERSION!r}"))
    if doc.get("kind") != "review_summary":
        problems.append(("kind", "kind must be 'review_summary'"))
    if not _s(doc.get("paper_id")):
        problems.append(("paper_id", "paper_id is required"))
    if not _s(doc.get("paper_version")):
        problems.append(("paper_version", "paper_version is required"))
    stage = doc.get("stage")
    if stage not in STAGES:
        problems.append(("stage", f"stage must be one of {STAGES}"))
    findings = doc.get("findings")
    if not isinstance(findings, list):
        problems.append(("findings", "findings must be a list"))
        return problems
    ids: list[str] = []
    for index, finding in enumerate(findings):
        path = f"$.findings[{index}]"
        if not isinstance(finding, dict):
            problems.append((path, "finding must be an object"))
            continue
        if not _s(finding.get("id")):
            problems.append((f"{path}.id", "id is required"))
        else:
            ids.append(finding["id"])
        if finding.get("severity") not in SEVERITIES:
            problems.append((f"{path}.severity", f"severity must be one of {SEVERITIES}"))
        category = finding.get("category")
        if category is not None and category not in FINDING_CATEGORIES:
            problems.append(
                (f"{path}.category", f"category must be one of {FINDING_CATEGORIES}")
            )
        if not _s(finding.get("location")):
            problems.append((f"{path}.location", "location is required"))
        if not _s(finding.get("problem")):
            problems.append((f"{path}.problem", "problem is required"))
        if "impact_on_conclusion" in finding and not isinstance(
            finding.get("impact_on_conclusion"), bool
        ):
            problems.append((f"{path}.impact_on_conclusion", "impact_on_conclusion must be a boolean"))
        related = finding.get("related_claims")
        if related is not None and not isinstance(related, list):
            problems.append((f"{path}.related_claims", "related_claims must be a list"))
    _unique(problems, "$.findings", ids)
    return problems


def validate_argument_map(doc: object) -> list[tuple[str, str]]:
    """Return [(path, problem)] for an argument map document."""
    problems: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("$", "argument map must be a JSON object")]
    if doc.get("schema_version") != SCHEMA_VERSION:
        problems.append(("schema_version", f"schema_version must be {SCHEMA_VERSION!r}"))
    if doc.get("kind") != "argument_map":
        problems.append(("kind", "kind must be 'argument_map'"))
    if not _s(doc.get("paper_id")):
        problems.append(("paper_id", "paper_id is required"))
    if not _s(doc.get("paper_version")):
        problems.append(("paper_version", "paper_version is required"))
    nodes = doc.get("nodes")
    if not isinstance(nodes, list):
        problems.append(("nodes", "nodes must be a list"))
        return problems
    ids: list[str] = []
    for index, node in enumerate(nodes):
        path = f"$.nodes[{index}]"
        if not isinstance(node, dict):
            problems.append((path, "node must be an object"))
            continue
        if not _s(node.get("id")):
            problems.append((f"{path}.id", "id is required"))
        else:
            ids.append(node["id"])
        if node.get("kind") not in NODE_KINDS:
            problems.append((f"{path}.kind", f"kind must be one of {NODE_KINDS}"))
        if not _s(node.get("text")):
            problems.append((f"{path}.text", "text is required"))
        for rel in ("depends_on", "supports", "evidence_refs"):
            value = node.get(rel)
            if value is not None and not isinstance(value, list):
                problems.append((f"{path}.{rel}", f"{rel} must be a list"))
    id_set = {value for value in ids}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        path = f"$.nodes[{index}]"
        for rel in ("depends_on", "supports"):
            for ref in node.get(rel) or []:
                if not isinstance(ref, str) or ref not in id_set:
                    problems.append((f"{path}.{rel}", f"unknown node id {ref!r}"))
    _unique(problems, "$.nodes", ids)
    return problems


def validate_revision_registry(doc: object) -> list[tuple[str, str]]:
    """Return [(path, problem)] for a revision registry document."""
    problems: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("$", "revision registry must be a JSON object")]
    if doc.get("schema_version") != SCHEMA_VERSION:
        problems.append(("schema_version", f"schema_version must be {SCHEMA_VERSION!r}"))
    if doc.get("kind") != "revision_registry":
        problems.append(("kind", "kind must be 'revision_registry'"))
    if not _s(doc.get("paper_id")):
        problems.append(("paper_id", "paper_id is required"))
    if not _s(doc.get("paper_version")):
        problems.append(("paper_version", "paper_version is required"))
    items = doc.get("items")
    if not isinstance(items, list):
        problems.append(("items", "items must be a list"))
        return problems
    ids: list[str] = []
    for index, item in enumerate(items):
        path = f"$.items[{index}]"
        if not isinstance(item, dict):
            problems.append((path, "revision item must be an object"))
            continue
        if not _s(item.get("id")):
            problems.append((f"{path}.id", "id is required"))
        else:
            ids.append(item["id"])
        if item.get("severity") not in SEVERITIES:
            problems.append((f"{path}.severity", f"severity must be one of {SEVERITIES}"))
        if not _s(item.get("location")):
            problems.append((f"{path}.location", "location is required"))
        if item.get("problem_type") not in PROBLEM_TYPES:
            problems.append(
                (f"{path}.problem_type", f"problem_type must be one of {PROBLEM_TYPES}")
            )
        for field_name in ("problem_description", "evidence", "recommended_change", "allowed_scope"):
            if not _s(item.get(field_name)):
                problems.append((f"{path}.{field_name}", f"{field_name} is required"))
        if item.get("human_status") not in HUMAN_STATUSES:
            problems.append(
                (f"{path}.human_status", f"human_status must be one of {HUMAN_STATUSES}")
            )
        deps = item.get("dependencies")
        if deps is not None and not isinstance(deps, list):
            problems.append((f"{path}.dependencies", "dependencies must be a list"))
    id_set = set(ids)
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        path = f"$.items[{index}]"
        for ref in item.get("dependencies") or []:
            if not isinstance(ref, str) or ref not in id_set:
                problems.append((f"{path}.dependencies", f"unknown revision id {ref!r}"))
    _unique(problems, "$.items", ids)
    return problems


def _load_json(path: Path) -> tuple[object, str | None]:
    try:
        raw = path.read_bytes().decode("utf-8")
        return json.loads(raw), None
    except Exception as exc:  # noqa: BLE001 - surface any read/parse problem
        return None, str(exc)


@dataclass
class ReviewFinding:
    rule_id: str
    bucket: str  # "error" | "warning"
    message: str
    path: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "bucket": self.bucket,
            "message": self.message,
            "path": self.path,
        }


@dataclass
class ReviewAuditResult:
    ok: bool
    errors: int
    warnings: int
    findings: list[ReviewFinding] = field(default_factory=list)
    directory: str = ""
    missing_files: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "findings": [finding.as_dict() for finding in self.findings],
            "directory": self.directory,
            "missing_files": self.missing_files,
            "hashes": self.hashes,
        }


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_review_dir(directory: Path, *, hashes: bool = False) -> ReviewAuditResult:
    """Audit a review directory: required files, machine-readable artifacts, versions sidecar."""
    findings: list[ReviewFinding] = []
    missing: list[str] = []
    for name in REQUIRED_REVIEW_MARKDOWN:
        if not (directory / name).is_file():
            missing.append(name)
            findings.append(
                ReviewFinding("REVIEW_FILE_MISSING", "error", f"missing file {name}", name)
            )
    registry: dict[str, str] = {}
    for name in OPTIONAL_REVIEW_JSON:
        path = directory / name
        if not path.is_file():
            continue
        doc, error = _load_json(path)
        if error is not None:
            findings.append(
                ReviewFinding("REVIEW_JSON_INVALID", "error", f"cannot parse {name}: {error}", name)
            )
            continue
        if name == "00-review-summary.json":
            problems = validate_review_summary(doc)
        elif name == "01-argument-map.json":
            problems = validate_argument_map(doc)
        else:
            problems = validate_revision_registry(doc)
        for path_name, message in problems:
            findings.append(
                ReviewFinding("REVIEW_SCHEMA", "error", message, f"{name}::{path_name}")
            )
    sidecar = directory / VERSION_SIDECAR
    if sidecar.is_file():
        try:
            for line in sidecar.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                digest, _, target = line.partition("  ")
                if len(digest) == 64 and target:
                    registry[target] = digest
        except OSError as exc:
            findings.append(
                ReviewFinding("VERSION_SIDECAR_UNREADABLE", "warning", str(exc), VERSION_SIDECAR)
            )
    else:
        findings.append(
            ReviewFinding("VERSION_SIDECAR_MISSING", "warning", "no versions.sha256 sidecar", VERSION_SIDECAR)
        )
    if hashes:
        for path in sorted(directory.glob("*.md")):
            registry[path.name] = _sha256(path)
    result = ReviewAuditResult(
        ok=not findings or all(f.bucket == "warning" for f in findings),
        errors=sum(1 for f in findings if f.bucket == "error"),
        warnings=sum(1 for f in findings if f.bucket == "warning"),
        findings=findings,
        directory=str(directory),
        missing_files=missing,
        hashes=registry,
    )
    return result


def scaffold_review_dir(directory: Path, *, paper_path: Path | None = None) -> list[Path]:
    """Create a review directory from installed, validated templates.

    Missing or corrupt package resources fail closed.  There is intentionally
    no blank-template fallback because it would create a misleading review
    workspace from an incomplete release.
    """
    try:
        template_dir = resource_traversable(*DEFAULT_TEMPLATE_RESOURCE)
        entries: list[tuple[str, bytes]] = []
        for resource in sorted(template_dir.iterdir(), key=lambda item: item.name):
            if not resource.is_file() or not resource.name.endswith((".md", ".json")):
                continue
            content = resource.read_bytes()
            if not content.strip():
                raise ThesisReviewResourceError("thesis-review template resource is invalid")
            content.decode("utf-8")
            if resource.name.endswith(".json") and not isinstance(json.loads(content), dict):
                raise ThesisReviewResourceError("thesis-review template resource is invalid")
            entries.append((resource.name, content))
        required = set(REQUIRED_REVIEW_MARKDOWN) | set(OPTIONAL_REVIEW_JSON)
        if not required.issubset({name for name, _ in entries}):
            raise ThesisReviewResourceError("thesis-review template resource set is incomplete")
    except ThesisReviewResourceError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ThesisReviewResourceError("thesis-review template resource is unavailable") from exc

    directory.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    for name, content in entries:
        target = directory / name
        if not target.exists():
            target.write_bytes(content)
            created.append(target)
    if paper_path is not None and paper_path.is_file():
        sidecar = directory / VERSION_SIDECAR
        if not sidecar.exists():
            sidecar.write_text(f"{_sha256(paper_path)}  {paper_path.name}\n", encoding="utf-8")
            created.append(sidecar)
    return created


def _cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="research-kb thesis-review",
        description="Init or validate a thesis_review review directory (independent optional capability).",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    init = subcommands.add_parser("init", help="Scaffold a review directory from templates")
    init.add_argument("directory", help="Review directory to create")
    init.add_argument("--paper", default=None, help="Thesis file path to record in versions.sha256")
    validate = subcommands.add_parser("validate", help="Audit a review directory")
    validate.add_argument("directory", help="Review directory to audit")
    validate.add_argument("--hashes", action="store_true", help="Also compute md file hashes")
    validate.add_argument("--strict", action="store_true", help="Exit 1 when errors are present")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _cli_parser().parse_args(argv)
    directory = Path(args.directory).resolve()
    if args.command == "init":
        created = scaffold_review_dir(
            directory, paper_path=Path(args.paper).resolve() if args.paper else None
        )
        print(json.dumps({"ok": True, "directory": str(directory), "created": [str(p) for p in created]}, ensure_ascii=False, indent=2))
        return 0
    result = audit_review_dir(directory, hashes=bool(getattr(args, "hashes", False)))
    print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    if args.strict and result.errors:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
