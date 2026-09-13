"""MR-3 isolated acquisition-staging validation.

The validator is offline. It reads one explicit staging directory, follows no
links, writes nothing, and emits a hash-bound dry-run ingest projection.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ..contract import canonical_sha256
from ..persistence.db import MaxControlError


STAGING_VALIDATION_SCHEMA = "max-research-acquisition-staging-validation/v1"
DRY_RUN_MANIFEST_SCHEMA = "max-research-acquisition-dry-run-projection/v1"
STAGING_VALIDATOR_VERSION = "research-kb/max-acquisition-staging-validator/v1"
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_CONTROL_OUTPUTS = {"sep-entries.jsonl", "bibliography.jsonl", "candidates.jsonl", "manual-queue.jsonl", "report.md"}
_ALLOWED_DOCUMENT_SUFFIXES = {".pdf", ".txt", ".md", ".html", ".htm", ".docx", ".epub"}
_PDF_MAGIC = b"%PDF-"
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

STAGING_VALIDATOR_VERSION_HASH = canonical_sha256({
    "validator": STAGING_VALIDATOR_VERSION,
    "document_suffixes": sorted(_ALLOWED_DOCUMENT_SUFFIXES),
    "control_outputs": sorted(_ALLOWED_CONTROL_OUTPUTS),
    "pdf_active_content": ["EmbeddedFile", "Encrypt", "JavaScript", "Launch", "OpenAction"],
    "archive_policy": "bounded-zip-no-links-no-active-content/v1",
})


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_link_or_reparse(path: Path) -> bool:
    """Reject symlinks and Windows junction/reparse points before resolving."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MaxControlError("staging path cannot be inspected safely") from exc
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return path.is_symlink() or os.path.islink(path) or bool(attributes & reparse_flag)


def _assert_unlinked_path(root: Path, relative: PurePosixPath) -> Path:
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if _is_link_or_reparse(candidate):
            raise MaxControlError("staging output path contains a link or reparse point")
    return candidate


def _strict_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise MaxControlError("staging manifest path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise MaxControlError("staging manifest path escapes its run directory")
    if ":" in path.parts[0] or value.casefold().startswith(("file:", "//")):
        raise MaxControlError("staging manifest path is not relative")
    return path


def _archive_risks(path: Path, *, suffix: str) -> list[str]:
    risks: set[str] = set()
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > 20_000:
                risks.add("archive_entry_count")
            names = {item.filename for item in infos}
            total_uncompressed = 0
            total_compressed = 0
            for item in infos:
                name = item.filename.replace("\\", "/")
                parts = PurePosixPath(name).parts
                if name.startswith("/") or any(part in {"..", ""} for part in parts) or (parts and ":" in parts[0]):
                    risks.add("archive_path_traversal")
                if item.flag_bits & 0x1:
                    risks.add("encrypted_archive_entry")
                if name.casefold().endswith(("vbaproject.bin", ".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".js", ".vbs")):
                    risks.add("active_or_executable_archive_content")
                total_uncompressed += int(item.file_size)
                total_compressed += int(item.compress_size)
            if total_uncompressed > max(256 * 1024 * 1024, path.stat().st_size * 250):
                risks.add("archive_expansion_limit")
            if total_uncompressed > 10 * 1024 * 1024 and total_compressed > 0 and total_uncompressed / total_compressed > 250:
                risks.add("archive_compression_ratio")
            if suffix == ".docx" and not {"[Content_Types].xml", "word/document.xml"}.issubset(names):
                raise MaxControlError("staged DOCX is structurally incomplete")
            if suffix == ".epub" and "META-INF/container.xml" not in names:
                raise MaxControlError("staged EPUB is structurally incomplete")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise MaxControlError("staged archive document is not a valid bounded ZIP container") from exc
    return sorted(risks)


def _pdf_risks(path: Path) -> list[str]:
    markers = {
        b"/JavaScript": "pdf_javascript",
        b"/Launch": "pdf_launch_action",
        b"/EmbeddedFile": "pdf_embedded_file",
        b"/OpenAction": "pdf_open_action",
        b"/Encrypt": "pdf_encrypted",
    }
    found: set[str] = set()
    overlap = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sample = overlap + chunk
            for marker, risk in markers.items():
                if marker in sample:
                    found.add(risk)
            overlap = sample[-32:]
    return sorted(found)


def _file_kind_and_risks(path: Path) -> tuple[str, list[str]]:
    suffix = path.suffix.casefold()
    if suffix not in _ALLOWED_DOCUMENT_SUFFIXES:
        raise MaxControlError("staged document format is unsupported")
    with path.open("rb") as handle:
        head = handle.read(8)
    if suffix == ".pdf" and not head.startswith(_PDF_MAGIC):
        raise MaxControlError("staged PDF failed its magic-byte check")
    if suffix in {".docx", ".epub"} and not head.startswith(_ZIP_MAGIC):
        raise MaxControlError("staged archive document failed its magic-byte check")
    risks = _pdf_risks(path) if suffix == ".pdf" else (_archive_risks(path, suffix=suffix) if suffix in {".docx", ".epub"} else [])
    return suffix[1:], risks


def validate_staging_run(
    staging_run: str | Path,
    *,
    max_candidates: int,
    max_total_bytes: int,
    existing_content_hashes: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Return a deterministic, non-ingesting validation and dry-run manifest."""

    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (max_candidates, max_total_bytes)):
        raise MaxControlError("staging validation caps are invalid")
    requested_root = Path(os.path.abspath(Path(staging_run).expanduser()))
    for component in reversed((requested_root, *requested_root.parents)):
        if component.exists() and _is_link_or_reparse(component):
            raise MaxControlError("staging run path must not contain a link or reparse point")
    root = requested_root.resolve(strict=True)
    if not root.is_dir():
        raise MaxControlError("staging run must be a real directory")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or _is_link_or_reparse(manifest_path) or manifest_path.stat().st_size > 8 * 1024 * 1024:
        raise MaxControlError("staging run lacks a bounded regular manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MaxControlError("staging manifest is not strict UTF-8 JSON") from exc
    allowed_manifest = {"schema_version", "worker", "run_id", "params", "inputs", "outputs", "started_at", "finished_at", "exit_code", "summary", "notes"}
    if not isinstance(manifest, Mapping) or set(manifest) - allowed_manifest or manifest.get("schema_version") != 1 or manifest.get("exit_code") != 0 or not isinstance(manifest.get("run_id"), str):
        raise MaxControlError("staging worker manifest is incomplete or has unknown fields")
    outputs = manifest.get("outputs")
    if not isinstance(outputs, list) or len(outputs) > max_candidates + 10_000:
        raise MaxControlError("staging worker output list is invalid")
    seen_paths: set[str] = set(); seen_hashes: set[str] = set(); documents: list[dict[str, Any]] = []
    total_bytes = 0
    for raw in outputs:
        if not isinstance(raw, Mapping) or set(raw) != {"path", "content_hash", "bytes"}:
            raise MaxControlError("staging output record is not strict")
        relative = _strict_relative(raw["path"]); relative_text = relative.as_posix()
        declared_hash = str(raw["content_hash"]).casefold(); declared_bytes = raw["bytes"]
        if not _HASH_RE.fullmatch(declared_hash) or isinstance(declared_bytes, bool) or not isinstance(declared_bytes, int) or declared_bytes < 0 or relative_text in seen_paths:
            raise MaxControlError("staging output hash, size, or identity is invalid")
        seen_paths.add(relative_text)
        candidate = _assert_unlinked_path(root, relative)
        if not candidate.is_file():
            raise MaxControlError("staging output is missing, non-regular, or linked")
        try:
            candidate.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise MaxControlError("staging output resolves outside the run directory") from exc
        actual_bytes = candidate.stat().st_size; actual_hash = _sha256_file(candidate)
        if actual_bytes != declared_bytes or actual_hash != declared_hash:
            raise MaxControlError("staging output differs from its signed manifest")
        total_bytes += actual_bytes
        if total_bytes > max_total_bytes:
            raise MaxControlError("staging run exceeds its authorized byte cap")
        if relative_text.startswith("files/"):
            kind, risks = _file_kind_and_risks(candidate)
            duplicate = actual_hash in seen_hashes or actual_hash in existing_content_hashes
            seen_hashes.add(actual_hash)
            documents.append({"relative_path": relative_text, "content_hash": actual_hash, "bytes": actual_bytes, "source_type": kind, "duplicate": duplicate, "risk_flags": risks, "manual_review_required": bool(risks), "eligible": not duplicate and not risks, "reliability_status": "unverified", "verification_status": "unverified"})
        elif relative_text not in _ALLOWED_CONTROL_OUTPUTS:
            raise MaxControlError("staging output is outside the allowed control files")
    if len(documents) > max_candidates:
        raise MaxControlError("staging document count exceeds its authorized cap")
    manifest_hash = _sha256_file(manifest_path)
    projection = {"schema": DRY_RUN_MANIFEST_SCHEMA, "staging_manifest_hash": manifest_hash, "worker_run_id": manifest["run_id"], "documents": documents, "document_count": len(documents), "eligible_count": sum(bool(item["eligible"]) for item in documents), "duplicate_count": sum(bool(item["duplicate"]) for item in documents), "manual_review_count": sum(bool(item["manual_review_required"]) for item in documents), "total_document_bytes": sum(int(item["bytes"]) for item in documents)}
    validation = {"schema": STAGING_VALIDATION_SCHEMA, "validator_version_hash": STAGING_VALIDATOR_VERSION_HASH, "worker_run_id": manifest["run_id"], "staging_manifest_hash": manifest_hash, "output_set_hash": canonical_sha256(sorted((item["path"], item["content_hash"], item["bytes"]) for item in outputs)), "document_count": len(documents), "total_bytes": total_bytes, "dry_run_manifest_hash": canonical_sha256(projection), "checks": {"paths_confined": True, "links_rejected": True, "hashes_match": True, "formats_allowed": True, "active_content_quarantined": True, "archive_expansion_checked": True, "duplicates_flagged": True, "authoritative_ingest_performed": False}}
    return {"validation": validation, "dry_run_manifest": projection, "validation_hash": canonical_sha256(validation)}


__all__ = ["DRY_RUN_MANIFEST_SCHEMA", "STAGING_VALIDATION_SCHEMA", "STAGING_VALIDATOR_VERSION", "STAGING_VALIDATOR_VERSION_HASH", "validate_staging_run"]
