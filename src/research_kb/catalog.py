from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import warnings
import time
import uuid
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from xml.etree import ElementTree

from .config import Limits, Settings
from .db import migrate
from .ingest import ingest_manifest
from .policy import Actor, PolicyError


SUPPORTED_EXTENSIONS = {".txt", ".md", ".html", ".htm", ".pdf", ".docx", ".epub"}
_TEXT_EXTENSIONS = {".txt", ".md", ".html", ".htm"}
_MEDIA_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg",
    ".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg", ".mp4", ".mkv", ".avi", ".mov",
}
_SOFTWARE_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".app", ".dmg", ".pkg",
    ".deb", ".rpm", ".jar", ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp",
    ".go", ".rs", ".ipynb", ".pdb", ".lib", ".so", ".class",
}
_DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".mdb", ".accdb"}
_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso"}
_TEMP_EXTENSIONS = {".tmp", ".temp", ".part", ".crdownload", ".download", ".bak", ".swp"}
_PRIVATE_TERMS = (
    "private", "personal", "unpublished", "draft", "homework", "assignment", "resume", "cv",
    "\u4e2a\u4eba", "\u79c1\u4eba", "\u672a\u53d1\u8868", "\u8349\u7a3f", "\u4f5c\u4e1a", "\u7b80\u5386", "\u9519\u9898", "\u8003\u516c", "\u65e5\u5fd7",
)
_CACHE_TERMS = (
    "cache", "temp", "tmp", "node_modules", "__pycache__", ".git", "download", "downloads", "logs", "log",
    "\u7f13\u5b58", "\u6d4f\u89c8\u5668", "recycle", "thumbs",
)
_ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MAX_TEXT_PROBE_BYTES = 8 * 1024 * 1024
_MAX_ZIP_PROBE_BYTES = 2 * 1024 * 1024
_QUICK_CHUNK_BYTES = 64 * 1024
_DEFAULT_MAX_HASH_BYTES = 512 * 1024 * 1024
_MAX_CONTAINER_PROBE_BYTES = 1 * 1024 * 1024
_PROBE_POLICY_VERSION = 8
_DEFAULT_POLICY_FILENAME = "catalog_policy.json"
_DEFAULT_PDF_MAX_PROBE_BYTES = 64 * 1024 * 1024
_DEFAULT_PDF_PROBE_TIMEOUT_SECONDS = 30.0
_PDF_PAGE_TEXT_LIMIT = 200_000
_PDF_PROBE_WORKER_SNIPPET = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from research_kb.catalog import _pdf_probe_work\n"
    "payload = json.load(sys.stdin)\n"
    "result = _pdf_probe_work(Path(payload['path']), payload.get('policy') or {})\n"
    "json.dump(result, sys.stdout)\n"
)


def _load_catalog_policy(path: str | Path | None = None) -> dict[str, Any]:
    policy_path = Path(path) if path is not None else Path(__file__).with_name(_DEFAULT_POLICY_FILENAME)
    try:
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CatalogError("catalog policy is unavailable or invalid") from exc
    if not isinstance(raw, dict):
        raise CatalogError("catalog policy must be an object")
    required_lists = ("private_terms", "discovery_terms", "cache_terms", "repository_markers", "repository_path_terms", "ocr_path_terms", "generated_path_terms", "generated_filename_patterns", "source_extensions")
    for key in required_lists:
        if not isinstance(raw.get(key), list) or any(not isinstance(value, str) or not value for value in raw[key]):
            raise CatalogError("catalog policy contains an invalid list")
    if not isinstance(raw.get("readme_pattern"), str) or not isinstance(raw.get("ready"), dict) or not isinstance(raw.get("forecast"), dict):
        raise CatalogError("catalog policy is incomplete")
    return raw




class CatalogError(PolicyError):
    """A sanitized catalog operation error."""


class CatalogInterrupted(CatalogError):
    """The scan stopped before its atomic final publish."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso_mtime(st: os.stat_result) -> str:
    return datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="microseconds")


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_write_json(path: Path, value: Any) -> None:
    _atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _atomic_write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    _atomic_write_text(
        path,
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
    )


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return default


def _read_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except (UnicodeError, json.JSONDecodeError):
                    continue
                if not isinstance(row, dict):
                    continue
                key = row.get("_record_key")
                if not isinstance(key, str) and row.get("root_alias") and row.get("relative_path"):
                    key = _record_key(str(row["root_alias"]), str(row["relative_path"]))
                if isinstance(key, str):
                    row["_record_key"] = key
                    rows[key] = row
    except (FileNotFoundError, OSError):
        pass
    return rows


def _is_reparse_or_link(path: Path, st: os.stat_result | None = None) -> bool:
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    is_junction = getattr(path, "is_junction", None)
    try:
        if is_junction is not None and is_junction():
            return True
    except OSError:
        return True
    if os.name == "nt":
        try:
            current = st or path.stat(follow_symlinks=False)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if getattr(current, "st_file_attributes", 0) & reparse:
                return True
        except OSError:
            return True
    return False


def _record_key(alias: str, relative_path: str) -> str:
    path_key = relative_path.casefold() if os.name == "nt" else relative_path
    return f"{alias}\0{path_key}"


def _validate_roots(root_specs: Iterable[str]) -> list[tuple[str, Path]]:
    roots: list[tuple[str, Path]] = []
    for supplied in root_specs:
        if "=" not in supplied:
            raise CatalogError("catalog roots must use ALIAS=PATH")
        alias, raw_path = supplied.split("=", 1)
        alias = alias.strip()
        if not _ALIAS_PATTERN.fullmatch(alias):
            raise CatalogError("catalog root alias is invalid")
        if not raw_path.strip():
            raise CatalogError("catalog root path is empty")
        try:
            resolved = Path(raw_path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise CatalogError("catalog root is unavailable") from exc
        if not resolved.is_dir() or _is_reparse_or_link(resolved):
            raise CatalogError("catalog root must be a regular directory")
        roots.append((alias, resolved))
    if not roots:
        raise CatalogError("at least one catalog root is required")
    if len({alias for alias, _ in roots}) != len(roots):
        raise CatalogError("catalog root aliases must be unique")
    for index, (_, first) in enumerate(roots):
        for _, second in roots[index + 1 :]:
            try:
                first.relative_to(second)
            except ValueError:
                pass
            else:
                raise CatalogError("catalog roots must not overlap")
            try:
                second.relative_to(first)
            except ValueError:
                pass
            else:
                raise CatalogError("catalog roots must not overlap")
    return roots


def _relative_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _path_tokens(relative_path: str) -> str:
    return relative_path.casefold().replace("\\", "/")


def _classify(relative_path: str, extension: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = policy or _load_catalog_policy()
    lowered = _path_tokens(relative_path)
    components = [part for part in lowered.split("/") if part]
    name = Path(relative_path).name.casefold()
    private_terms = tuple(policy["private_terms"])
    discovery_terms = tuple(policy["discovery_terms"])
    cache_terms = tuple(policy["cache_terms"])
    private_hits = [term for term in private_terms if term.casefold() in lowered or term.casefold() in name]
    discovery_hits = [term for term in discovery_terms if term.casefold() in lowered or term.casefold() in name]
    cache_hits = [term for term in cache_terms if term.casefold() in lowered]
    repository_markers = [term.casefold() for term in policy["repository_markers"]]
    repository_path_terms = [term.casefold() for term in policy["repository_path_terms"]]
    generated_path_terms = [term.casefold() for term in policy["generated_path_terms"]]
    ocr_path_terms = [term.casefold() for term in policy["ocr_path_terms"]]
    repo_marker_hits = [term for term in repository_markers if term in components or term in lowered]
    src_packages_tree = "src" in components and "packages" in components
    source_extension = extension in {value.casefold() for value in policy["source_extensions"]}
    readme_file = bool(re.fullmatch(policy["readme_pattern"], name))
    code_repository = bool(repo_marker_hits or src_packages_tree or (source_extension and "packages" in components))
    repository_document = bool(readme_file and (code_repository or "readme" in name))
    generated_path_hits = [term for term in generated_path_terms if term in components]
    ocr_path_hits = [term for term in ocr_path_terms if term in components]
    generated_name_hits = [pattern for pattern in policy["generated_filename_patterns"] if re.search(pattern, name)]
    ocr_page_fragment = bool(ocr_path_hits or re.fullmatch(r"(?:page|p)[_-]?\d{3,6}\.txt", name))
    generated_derivative = bool(ocr_page_fragment or generated_path_hits or generated_name_hits)
    if extension in _MEDIA_EXTENSIONS:
        file_kind = "media"
    elif extension in _SOFTWARE_EXTENSIONS or source_extension:
        file_kind = "source_code" if source_extension else "software"
    elif extension in _DATABASE_EXTENSIONS:
        file_kind = "database"
    elif extension in _ARCHIVE_EXTENSIONS:
        file_kind = "archive"
    elif extension in SUPPORTED_EXTENSIONS:
        file_kind = "document"
    elif extension in _TEMP_EXTENSIONS:
        file_kind = "temporary"
    else:
        file_kind = "unknown"
    if cache_hits or extension in _TEMP_EXTENSIONS or "logs" in components or "log" in components:
        file_kind = "cache"
    if code_repository or repository_document:
        file_kind = "source_code"
    zotero_storage = "zotero" in components and "storage" in components and file_kind == "document"
    if zotero_storage:
        file_kind = "zotero_storage"
    supported = extension in SUPPORTED_EXTENSIONS and file_kind in {"document", "zotero_storage"} and not code_repository and not repository_document and not cache_hits
    privacy_classification = "personal_material_review" if private_hits else ("discovery_collection_review" if discovery_hits else None)
    inferred_title = Path(relative_path).stem if extension in SUPPORTED_EXTENSIONS and not ocr_page_fragment else None
    source_type_candidate = "web_page" if extension in {".html", ".htm"} else ("document" if extension in SUPPORTED_EXTENSIONS else "unknown")
    classification_reasons = []
    classification_reasons.extend(f"private_term:{hit}" for hit in private_hits)
    classification_reasons.extend(f"discovery_term:{hit}" for hit in discovery_hits)
    classification_reasons.extend(f"repository_marker:{hit}" for hit in repo_marker_hits)
    classification_reasons.extend(f"generated_path:{hit}" for hit in generated_path_hits)
    classification_reasons.extend(f"generated_filename:{hit}" for hit in generated_name_hits)
    if ocr_page_fragment:
        classification_reasons.append("ocr_page_fragment")
    return {
        "file_kind": file_kind,
        "supported_by_current_ingest": supported,
        "possible_private_or_unpublished": bool(private_hits or discovery_hits),
        "privacy_classification": privacy_classification,
        "privacy_reasons": [f"path_term:{hit}" for hit in private_hits + discovery_hits],
        "cache_reasons": [f"path_term:{hit}" for hit in cache_hits],
        "classification_reasons": classification_reasons,
        "code_repository": code_repository,
        "repository_document": repository_document,
        "generated_derivative": generated_derivative,
        "generated_derivative_type": "ocr_page_fragment" if ocr_page_fragment else ("generated_output" if generated_derivative else None),
        "ocr_page_fragment": ocr_page_fragment,
        "zotero_storage": zotero_storage,
        "inferred_title": inferred_title,
        "source_type_candidate": source_type_candidate,
    }


def _looks_like_local_path(value: str) -> bool:
    candidate = value.strip()
    return bool(re.match(r"^(?:[A-Za-z]:[\\/]|\\\\|//|/|file://)", candidate, flags=re.IGNORECASE))


def _redact_local_paths(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_local_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_local_paths(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_local_paths(item) for item in value]
    if isinstance(value, str) and _looks_like_local_path(value):
        return "unverified_path_redacted"
    return value


def _safe_metadata_value(value: Any, maximum: int = 500) -> str | None:
    if value is None:
        return None
    value = str(value).replace("\\x00", " ").strip()
    if _looks_like_local_path(value):
        return "unverified_path_redacted"
    return value[:maximum] if value else None

def _probe_text(path: Path, size_bytes: int) -> dict[str, Any]:
    encodings = ("utf-8-sig", "utf-8", "gb18030", "cp1252")
    selected: str | None = None
    selected_stats: dict[str, Any] | None = None
    for encoding in encodings:
        stats = {"char_count": 0, "non_whitespace_chars": 0, "replacement_chars": 0, "nul_chars": 0, "text_bytes": 0, "bytes_read": 0, "probe_truncated": False}
        try:
            import codecs
            decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
            with path.open("rb") as handle:
                remaining = _MAX_TEXT_PROBE_BYTES
                while remaining > 0:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    stats["bytes_read"] += len(chunk)
                    remaining -= len(chunk)
                    text = decoder.decode(chunk, final=False)
                    stats["char_count"] += len(text)
                    stats["non_whitespace_chars"] += sum(1 for char in text if not char.isspace())
                    stats["replacement_chars"] += text.count("\ufffd")
                    stats["nul_chars"] += text.count("\x00")
                    stats["text_bytes"] += len(text.encode("utf-8", errors="ignore"))
                text = decoder.decode(b"", final=True)
                stats["char_count"] += len(text)
                stats["non_whitespace_chars"] += sum(1 for char in text if not char.isspace())
                stats["replacement_chars"] += text.count("\ufffd")
                stats["nul_chars"] += text.count("\x00")
                stats["text_bytes"] += len(text.encode("utf-8", errors="ignore"))
            stats["probe_truncated"] = stats["bytes_read"] < size_bytes
            selected, selected_stats = encoding, stats
            break
        except (UnicodeDecodeError, OSError):
            continue
    if selected is None or selected_stats is None:
        return {"status": "invalid_encoding", "method": "streaming-text", "reasons": ["not_decodable_by_supported_text_encodings"], "probe": {"bytes_read": 0, "char_count": 0, "estimated_text_bytes": 0}, "metadata": {}}
    if selected_stats["char_count"] == 0 or selected_stats["non_whitespace_chars"] == 0:
        status, reasons = "empty", ["empty_or_whitespace_only"]
    elif selected not in {"utf-8", "utf-8-sig"}:
        status, reasons = "fallback_encoding", [f"decoded_with:{selected}", "manifest_should_record_encoding_review"]
    elif selected_stats["replacement_chars"] or selected_stats["nul_chars"]:
        status, reasons = "suspicious_text", ["replacement_or_nul_character_detected"]
    else:
        status, reasons = "ok", []
    estimated_bytes = selected_stats["text_bytes"]
    if selected_stats["probe_truncated"] and selected_stats["bytes_read"]:
        estimated_bytes = min(size_bytes * 4, int(estimated_bytes * size_bytes / selected_stats["bytes_read"]))
    probe = dict(selected_stats)
    probe.update({"encoding": selected, "estimated_text_bytes": max(0, estimated_bytes), "estimated_passages": max(0, math.ceil(selected_stats["char_count"] / 2400))})
    return {"status": status, "method": f"streaming-{selected}", "reasons": reasons, "probe": probe, "metadata": {}}

def _parse_xml_metadata(handle: Any, *, limit: int = 512 * 1024) -> dict[str, str]:
    raw = handle.read(limit + 1)
    if len(raw) > limit:
        raw = raw[:limit]
    root = ElementTree.fromstring(raw)
    result: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].casefold() if isinstance(element.tag, str) else ""
        if tag in {"title", "creator", "author", "date", "publisher", "identifier", "subject"}:
            value = _safe_metadata_value(element.text)
            if value and tag not in result:
                result[tag] = value
    return result


def _probe_zip(path: Path, extension: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > _MAX_CONTAINER_PROBE_BYTES:
            return {"status": "unavailable", "method": "bounded-zip-probe", "reasons": ["container_exceeds_bounded_probe_size"], "probe": {"probe_deferred": True}, "metadata": {}}
    except OSError:
        return {"status": "corrupt", "method": "bounded-zip-probe", "reasons": ["container_stat_failed"], "probe": {}, "metadata": {}}
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            metadata: dict[str, str] = {}
            char_count = 0
            non_whitespace = 0
            bytes_read = 0
            if extension == ".docx":
                if "word/document.xml" not in names:
                    return {"status": "corrupt", "method": "zip+xml", "reasons": ["missing_word_document"], "probe": {}, "metadata": {}}
                with archive.open("word/document.xml") as handle:
                    for _, element in ElementTree.iterparse(handle, events=("end",)):
                        tag = element.tag.rsplit("}", 1)[-1] if isinstance(element.tag, str) else ""
                        if tag == "t":
                            value = element.text or ""
                            char_count += len(value)
                            non_whitespace += sum(1 for char in value if not char.isspace())
                        element.clear()
                if "docProps/core.xml" in names:
                    try:
                        with archive.open("docProps/core.xml") as handle:
                            metadata = _parse_xml_metadata(handle)
                    except (OSError, ElementTree.ParseError, KeyError):
                        metadata = {}
                method = "zip+xml-docx"
            else:
                html_names = [name for name in names if name.casefold().endswith((".html", ".htm", ".xhtml"))]
                if not html_names:
                    return {"status": "corrupt", "method": "zip+html", "reasons": ["missing_epub_content"], "probe": {}, "metadata": {}}
                for name in html_names:
                    if bytes_read >= _MAX_ZIP_PROBE_BYTES:
                        break
                    with archive.open(name) as handle:
                        remaining = _MAX_ZIP_PROBE_BYTES - bytes_read
                        while remaining > 0:
                            chunk = handle.read(min(256 * 1024, remaining))
                            if not chunk:
                                break
                            bytes_read += len(chunk)
                            remaining -= len(chunk)
                            text = chunk.decode("utf-8", errors="replace")
                            char_count += len(text)
                            non_whitespace += sum(1 for char in text if not char.isspace())
                opf_names = [name for name in names if name.casefold().endswith(".opf")]
                if opf_names:
                    try:
                        with archive.open(opf_names[0]) as handle:
                            metadata = _parse_xml_metadata(handle)
                    except (OSError, ElementTree.ParseError, KeyError):
                        metadata = {}
                method = "zip+html-epub"
            if char_count == 0 or non_whitespace == 0:
                status, reasons = "empty", ["container_has_no_nonempty_text"]
            else:
                status, reasons = "ok", []
            return {"status": status, "method": method, "reasons": reasons, "probe": {"char_count": char_count, "non_whitespace_chars": non_whitespace, "estimated_text_bytes": max(char_count, non_whitespace), "estimated_passages": max(1, math.ceil(char_count / 2400)) if char_count else 0, "probe_truncated": extension == ".epub" and bytes_read >= _MAX_ZIP_PROBE_BYTES}, "metadata": metadata}
    except (OSError, zipfile.BadZipFile, RuntimeError, ElementTree.ParseError, KeyError):
        return {"status": "corrupt", "method": "zip", "reasons": ["invalid_or_unreadable_container"], "probe": {}, "metadata": {}}


def _pdf_probe_work(path: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """Run the pypdf-based page sample inside the isolated probe worker."""

    forecast_policy = policy.get("forecast", {})
    try:
        from pypdf import PdfReader
    except ImportError:
        base_probe = {"header_valid": True, "pages": None, "has_text_layer": None, "probe_bounded": True, "probe_dependency": "pypdf", "pdf_probe_status": "probe_pending", "ocr_status": "probe_pending", "probe_deferred": True, "probe_deferred_reason": "pypdf_optional_dependency_unavailable"}
        return {"status": "pending", "method": "pdf-bounded-probe", "reasons": ["pdf_probe_pending_optional_dependency", "ocr_status_unknown"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}
    base_probe = {"header_valid": True, "pages": None, "has_text_layer": None, "probe_bounded": True, "probe_dependency": "pypdf"}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            reader = PdfReader(str(path), strict=False)
            if reader.is_encrypted:
                base_probe.update({"pdf_probe_status": "encrypted", "ocr_status": "encrypted"})
                return {"status": "encrypted", "method": "pypdf-bounded-probe", "reasons": ["pdf_reader_reports_encrypted"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}
            page_count = len(reader.pages)
            if page_count <= 0:
                base_probe.update({"pdf_probe_status": "corrupt", "ocr_status": "corrupt", "pages": 0})
                return {"status": "corrupt", "method": "pypdf-bounded-probe", "reasons": ["pdf_has_no_pages"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}
            requested = {0, page_count // 2, page_count - 1}
            page_numbers = sorted(index for index in requested if 0 <= index < page_count)
            sampled_chars = 0
            pages_with_text = 0
            sampled = []
            for index in page_numbers[: int(forecast_policy.get("pdf_page_sample_count", 3))]:
                text = (reader.pages[index].extract_text() or "")[:_PDF_PAGE_TEXT_LIMIT]
                chars = len(text.strip())
                sampled_chars += chars
                pages_with_text += int(bool(chars))
                sampled.append(index + 1)
            has_text_layer = pages_with_text > 0
            estimated_chars = int(sampled_chars / max(1, len(sampled)) * page_count)
            metadata = {}
            provenance = {}
            info = reader.metadata or {}
            title = _safe_metadata_value(info.get("/Title"))
            author = _safe_metadata_value(info.get("/Author"))
            creator = _safe_metadata_value(info.get("/Creator"))
            if title:
                metadata["title"] = title
                provenance["title"] = "embedded_file_creator_unverified"
            if author:
                metadata["file_author"] = author
                provenance["author"] = "embedded_file_creator_unverified"
            if creator:
                metadata["file_creator"] = creator
                provenance["creator"] = "embedded_file_creator_unverified"
            base_probe.update({"pdf_probe_status": "confirmed_text_layer" if has_text_layer else "confirmed_needs_ocr", "ocr_status": "confirmed_text_layer" if has_text_layer else "confirmed_needs_ocr", "pages": page_count, "sampled_page_numbers": sampled, "sampled_char_count": sampled_chars, "sampled_pages_with_text": pages_with_text, "has_text_layer": has_text_layer, "suspected_scanned": not has_text_layer, "estimated_text_bytes": estimated_chars * 2, "estimated_passages": max(1, math.ceil(estimated_chars / 2400)) if estimated_chars else 0, "probe_deferred": False})
            status = "ok" if has_text_layer else "needs_ocr"
            reasons = ["bounded_samples_have_text_layer"] if has_text_layer else ["bounded_samples_have_no_text_layer", "ocr_required_for_text_access"]
            return {"status": status, "method": "pypdf-bounded-page-sample", "reasons": reasons, "probe": base_probe, "metadata": metadata, "metadata_provenance": provenance}
    except Exception:
        base_probe.update({"pdf_probe_status": "corrupt", "ocr_status": "corrupt", "probe_error_sanitized": True})
        return {"status": "corrupt", "method": "pypdf-bounded-probe", "reasons": ["pdf_reader_failed_safely"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}


def _probe_pdf(path: Path, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = policy or _load_catalog_policy()
    forecast_policy = policy.get("forecast", {})
    max_bytes = int(forecast_policy.get("pdf_max_probe_bytes", _DEFAULT_PDF_MAX_PROBE_BYTES))
    timeout_seconds = float(forecast_policy.get("pdf_probe_timeout_seconds", _DEFAULT_PDF_PROBE_TIMEOUT_SECONDS))
    try:
        size_bytes = path.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(64 * 1024)
    except OSError:
        return {"status": "corrupt", "method": "pdf-bounded-probe", "reasons": ["pdf_header_read_failed"], "probe": {"pdf_probe_status": "corrupt", "ocr_status": "corrupt"}, "metadata": {}, "metadata_provenance": {}}
    if not header.startswith(b"%PDF-"):
        return {"status": "corrupt", "method": "pdf-bounded-probe", "reasons": ["pdf_header_missing"], "probe": {"pdf_probe_status": "corrupt", "ocr_status": "corrupt"}, "metadata": {}, "metadata_provenance": {}}
    base_probe = {"header_valid": True, "pages": None, "has_text_layer": None, "probe_bounded": True, "probe_dependency": "pypdf"}
    if b"/Encrypt" in header:
        base_probe.update({"pdf_probe_status": "encrypted", "ocr_status": "encrypted"})
        return {"status": "encrypted", "method": "pdf-bounded-probe", "reasons": ["pdf_encryption_marker_or_reader_encrypted"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}
    if size_bytes > max_bytes:
        base_probe.update({"pdf_probe_status": "probe_pending", "ocr_status": "probe_pending", "probe_deferred": True, "probe_deferred_reason": "pdf_exceeds_bounded_probe_size"})
        return {"status": "pending", "method": "pdf-bounded-probe", "reasons": ["pdf_probe_pending_bounded_size", "ocr_status_unknown"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}
    payload = json.dumps({"path": str(path), "policy": policy}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", _PDF_PROBE_WORKER_SNIPPET],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        try:
            raw, _ = proc.communicate(input=payload, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            base_probe.update({"pdf_probe_status": "probe_pending", "ocr_status": "probe_pending", "probe_deferred": True, "probe_deferred_reason": "pdf_probe_timeout"})
            return {"status": "pending", "method": "pdf-bounded-probe", "reasons": ["pdf_probe_timeout", "ocr_status_unknown"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}
        if proc.returncode != 0:
            base_probe.update({"pdf_probe_status": "corrupt", "ocr_status": "corrupt", "probe_error_sanitized": True})
            return {"status": "corrupt", "method": "pdf-bounded-probe", "reasons": ["pdf_worker_failed_safely"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            result = None
        if not isinstance(result, dict) or not isinstance(result.get("probe"), dict):
            base_probe.update({"pdf_probe_status": "corrupt", "ocr_status": "corrupt", "probe_error_sanitized": True})
            return {"status": "corrupt", "method": "pdf-bounded-probe", "reasons": ["pdf_worker_output_invalid"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}
        return result
    except OSError:
        base_probe.update({"pdf_probe_status": "probe_pending", "ocr_status": "probe_pending", "probe_deferred": True, "probe_deferred_reason": "pdf_worker_spawn_failed"})
        return {"status": "pending", "method": "pdf-bounded-probe", "reasons": ["pdf_probe_pending_worker_unavailable", "ocr_status_unknown"], "probe": base_probe, "metadata": {}, "metadata_provenance": {}}


def _probe_file(path: Path, extension: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    if extension in _TEXT_EXTENSIONS:
        return _probe_text(path, path.stat().st_size)
    if extension == ".pdf":
        return _probe_pdf(path, policy)
    if extension in {".docx", ".epub"}:
        return _probe_zip(path, extension)
    return {"status": "not_run", "method": "unsupported", "reasons": ["extension_not_supported"], "probe": {}, "metadata": {}}


def _quick_fingerprint(path: Path, size_bytes: int) -> str:
    digest = hashlib.sha256()
    digest.update(str(size_bytes).encode("ascii"))
    with path.open("rb") as handle:
        digest.update(handle.read(_QUICK_CHUNK_BYTES))
        if size_bytes > _QUICK_CHUNK_BYTES:
            handle.seek(max(0, size_bytes - _QUICK_CHUNK_BYTES))
            digest.update(handle.read(_QUICK_CHUNK_BYTES))
    return digest.hexdigest()


def _full_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _stat_signature(st: os.stat_result) -> tuple[int, int]:
    return int(st.st_size), int(st.st_mtime_ns)


def _metadata_profile(record: dict[str, Any]) -> dict[str, Any]:
    candidates = dict(record.get("metadata_candidates") or {})
    profile: dict[str, Any] = {"type": "unknown"}
    for key in ("authors", "title", "container_title", "year", "volume", "issue", "page_range", "doi", "publisher", "editors", "translators", "edition", "place", "isbn"):
        profile[key] = candidates.get(key, "unknown")
    profile.update({"inferred_title": record.get("inferred_title", "unknown"), "source_type": record.get("source_type_candidate", "unknown"), "source_type_provenance": record.get("source_type_provenance", "unknown"), "metadata_provenance": record.get("metadata_provenance", {"title": "unknown", "author": "unknown", "type": "unknown"}), "document_id": "unknown", "content_hash": record.get("sha256", "unknown"), "source_version": "unknown"})
    return profile


class CatalogScanner:
    _READINESS_LEVELS = (
        "ingest_ready",
        "search_ready",
        "citation_ready",
        "evidence_ready",
        "report_ready",
    )

    def __init__(self, roots: Iterable[tuple[str, Path]], output: str | Path, *, candidate_limit: int = 450, max_hash_bytes: int = _DEFAULT_MAX_HASH_BYTES, checkpoint_interval: int = 250, progress: Callable[[dict[str, Any]], None] | None = None, policy_path: str | Path | None = None) -> None:
        self.roots = [(alias, path.resolve()) for alias, path in roots]
        self.output = Path(output).expanduser().resolve()
        self.candidate_limit = max(1, int(candidate_limit))
        self.max_hash_bytes = max(1, int(max_hash_bytes))
        self.checkpoint_interval = max(1, int(checkpoint_interval))
        self.progress = progress
        self.policy = _load_catalog_policy(policy_path)
        for _, root in self.roots:
            try:
                self.output.relative_to(root)
            except ValueError:
                pass
            else:
                raise CatalogError("catalog output must be outside source roots")
        self.output.mkdir(parents=True, exist_ok=True)
        self.partial_path = self.output / ".catalog.inprogress.jsonl"
        self.state_path = self.output / "scan-state.json"
        self.scan_errors: Counter[str] = Counter()
        self.scan_id = uuid.uuid4().hex
        self.started_at = _now()

    def _discover(self) -> list[tuple[str, str, Path, os.stat_result, bool]]:
        discovered: list[tuple[str, str, Path, os.stat_result, bool]] = []
        for alias, root in self.roots:
            stack = [root]
            while stack:
                directory = stack.pop()
                try:
                    entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
                except OSError:
                    self.scan_errors["directory_unreadable"] += 1
                    continue
                for entry in entries:
                    path = Path(entry.path)
                    relative = _relative_path(root, path)
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        self.scan_errors["file_stat_failed"] += 1
                        continue
                    link_like = _is_reparse_or_link(path, st)
                    if link_like:
                        discovered.append((alias, relative, path, st, True))
                    elif stat.S_ISDIR(st.st_mode):
                        stack.append(path)
                    elif stat.S_ISREG(st.st_mode):
                        discovered.append((alias, relative, path, st, False))
                    else:
                        discovered.append((alias, relative, path, st, True))
        discovered.sort(key=lambda item: (item[0], item[1].casefold() if os.name == "nt" else item[1]))
        return discovered

    def _base_record(self, alias: str, relative: str, st: os.stat_result, link_like: bool, previous: dict[str, Any] | None) -> dict[str, Any]:
        extension = Path(relative).suffix.casefold()
        classification = _classify(relative, extension, self.policy)
        record_key = _record_key(alias, relative)
        record: dict[str, Any] = {
            "_record_key": record_key,
            "catalog_record_id": (previous or {}).get("catalog_record_id", "cat_" + hashlib.sha256(record_key.encode("utf-8")).hexdigest()[:20]),
            "root_alias": alias,
            "relative_path": relative,
            "extension": extension,
            "size_bytes": int(st.st_size),
            "modified_time": _iso_mtime(st),
            "file_kind": "link" if link_like else classification["file_kind"],
            "supported_by_current_ingest": bool(classification["supported_by_current_ingest"] and not link_like),
            "technical_status": "unsupported_format" if link_like else "unprobed",
            "technical_reasons": ["link_like_not_followed"] if link_like else [],
            "metadata_status": "unknown",
            "extraction_probe_status": "not_run" if link_like else "pending",
            "extraction_method_candidate": "not_run" if link_like else "unknown",
            "hash_status": "not_requested" if link_like else "pending",
            "sha256": None,
            "quick_fingerprint": None,
            "duplicate_group_id": None,
            "duplicate_comparison_bucket": None,
            "duplicate_status": "none",
            "possible_generated_derivative": bool(classification["generated_derivative"]),
            "generated_derivative_type": classification["generated_derivative_type"],
            "ocr_page_fragment": bool(classification["ocr_page_fragment"]),
            "possible_private_or_unpublished": bool(classification["possible_private_or_unpublished"]),
            "privacy_classification": classification["privacy_classification"],
            "privacy_status": "review_required" if classification["possible_private_or_unpublished"] else "not_flagged",
            "code_repository": bool(classification["code_repository"]),
            "repository_document": bool(classification["repository_document"]),
            "selection_status": "excluded" if link_like else "pending",
            "selection_reasons": list(classification["privacy_reasons"]),
            "first_seen_at": (previous or {}).get("first_seen_at", _now()),
            "last_scanned_at": _now(),
            "present": True,
            "change_state": "modified" if previous and previous.get("present", True) else "new",
            "zotero_status": "zotero_attachment_unmapped" if classification["zotero_storage"] else "not_zotero_storage",
            "metadata_candidates": {},
            "metadata_provenance": {"title": "unknown", "author": "unknown", "type": "unknown"},
            "inferred_title": classification["inferred_title"],
            "source_type_candidate": classification["source_type_candidate"],
            "source_type_provenance": "unknown",
            "ocr_status": "not_applicable",
            "pdf_probe_status": "not_applicable",
            "probe": {},
            "scan_signature": list(_stat_signature(st)),
            "probe_policy_version": _PROBE_POLICY_VERSION,
            "readiness": {level: False for level in self._READINESS_LEVELS},
        }
        record["selection_reasons"].extend(classification["cache_reasons"])
        if link_like:
            record["selection_reasons"].append("links_and_reparse_points_are_not_followed")
        return record

    @staticmethod
    def _cache_matches(previous: dict[str, Any], st: os.stat_result, quick: str) -> bool:
        return bool(previous.get("present", True) and previous.get("probe_policy_version") == _PROBE_POLICY_VERSION and previous.get("scan_signature") == list(_stat_signature(st)) and previous.get("quick_fingerprint") == quick and previous.get("extraction_probe_status") not in {"pending", "not_run"})

    def _process_one(self, alias: str, relative: str, path: Path, st: os.stat_result, link_like: bool, previous: dict[str, Any] | None) -> dict[str, Any]:
        record = self._base_record(alias, relative, st, link_like, previous)
        if link_like:
            return record
        try:
            quick = _quick_fingerprint(path, int(st.st_size))
            current = path.stat()
        except OSError:
            record.update({"technical_status": "corrupt_or_unreadable", "technical_reasons": ["file_stat_or_quick_fingerprint_failed"], "extraction_probe_status": "unavailable", "hash_status": "unavailable"})
            return record
        if previous and self._cache_matches(previous, current, quick):
            cached = dict(previous)
            cached.update({"present": True, "change_state": "unchanged", "last_scanned_at": _now(), "size_bytes": int(current.st_size), "modified_time": _iso_mtime(current), "scan_signature": list(_stat_signature(current))})
            return cached
        classification = _classify(relative, Path(relative).suffix.casefold(), self.policy)
        record["quick_fingerprint"] = quick
        record["selection_reasons"].extend(classification["classification_reasons"])
        if classification["possible_private_or_unpublished"]:
            record.update({"technical_status": "privacy_review", "technical_reasons": list(classification["privacy_reasons"]), "extraction_probe_status": "not_run_privacy_review", "hash_status": "not_requested_privacy_review"})
        elif classification["generated_derivative"]:
            record.update({"technical_status": "generated_derivative", "technical_reasons": list(classification["classification_reasons"]) + ["generated_derivative_not_imported_as_independent_source"], "extraction_probe_status": "not_run_generated_derivative", "hash_status": "not_requested_generated_derivative"})
        elif classification["code_repository"] or classification["repository_document"]:
            record.update({"technical_status": "software_or_cache", "technical_reasons": list(classification["classification_reasons"]) + ["repository_or_project_document_review"], "extraction_probe_status": "not_run_repository_review", "hash_status": "not_requested_repository_review"})
        elif not classification["supported_by_current_ingest"]:
            if classification["file_kind"] == "media":
                status, reasons = "media_deferred", ["media_not_directly_imported"]
            elif classification["file_kind"] in {"software", "source_code", "cache"}:
                status, reasons = "software_or_cache", ["software_cache_or_program_file"]
            else:
                status, reasons = "unsupported_format", ["extension_not_supported_by_current_ingest"]
            record.update({"technical_status": status, "technical_reasons": reasons, "extraction_probe_status": "not_run", "hash_status": "not_requested"})
        else:
            try:
                result = _probe_file(path, Path(relative).suffix.casefold(), self.policy)
            except (OSError, ValueError, RuntimeError):
                result = {"status": "corrupt", "method": "bounded-probe", "reasons": ["probe_failed"], "probe": {}, "metadata": {}, "metadata_provenance": {}}
            record["extraction_probe_status"] = result["status"]
            record["extraction_method_candidate"] = result["method"]
            record["technical_reasons"] = list(result.get("reasons", []))
            record["probe"] = result.get("probe", {})
            record["metadata_candidates"] = result.get("metadata", {})
            if Path(relative).suffix.casefold() == ".docx":
                file_creator = record["metadata_candidates"].pop("creator", None)
                if file_creator:
                    record["metadata_candidates"]["file_creator"] = file_creator
                record["metadata_provenance"] = {key: "embedded_file_creator_unverified" for key in record["metadata_candidates"]}
            elif Path(relative).suffix.casefold() == ".epub" and record["metadata_candidates"]:
                creator = record["metadata_candidates"].pop("creator", None)
                if creator and not record["metadata_candidates"].get("authors") and not record["metadata_candidates"].get("editors"):
                    record["metadata_candidates"]["authors"] = [creator]
                record["metadata_provenance"] = {key: "embedded_bibliographic" for key in record["metadata_candidates"]}
                record["source_type_candidate"] = "book"
                record["source_type_provenance"] = "embedded_bibliographic"
            else:
                record["metadata_provenance"] = result.get("metadata_provenance", {}) or {}
            record["source_type_candidate"] = result.get("source_type_candidate") or record.get("source_type_candidate") or classification["source_type_candidate"]
            if record.get("source_type_provenance") == "unknown":
                record["source_type_provenance"] = record["metadata_provenance"].get("type", "unknown") if isinstance(record["metadata_provenance"], dict) else "unknown"
            if record["metadata_candidates"]:
                record["metadata_status"] = "embedded_bibliographic" if any(value == "embedded_bibliographic" for value in record["metadata_provenance"].values()) else "embedded_file_creator_unverified"
            elif record.get("inferred_title"):
                record["metadata_status"] = "filename_inferred"
            else:
                record["metadata_status"] = "unknown"
            record["ocr_status"] = record["probe"].get("ocr_status", "not_applicable")
            record["pdf_probe_status"] = record["probe"].get("pdf_probe_status", "not_applicable")
            status = result["status"]
            if status == "ok":
                record["technical_status"] = "needs_metadata_review" if record["metadata_status"] not in {"embedded_bibliographic", "manually_verified", "zotero_mapped"} else "ready_for_manifest"
                record["selection_reasons"].append("extractable_nonempty_text")
            elif status == "needs_ocr":
                record["technical_status"] = "needs_ocr"
            elif status == "encrypted":
                record["technical_status"] = "encrypted"
            elif status in {"pending", "unavailable"}:
                record["technical_status"] = "needs_extraction_review"
            elif status in {"empty", "fallback_encoding", "suspicious_text", "invalid_encoding"}:
                record["technical_status"] = "needs_extraction_review"
            else:
                record["technical_status"] = "corrupt_or_unreadable"
            record["hash_status"] = "pending"
        try:
            after = path.stat()
        except OSError:
            after = None
        stable = after is not None and _stat_signature(after) == _stat_signature(st)
        if stable:
            try:
                stable = _quick_fingerprint(path, int(after.st_size)) == quick
            except OSError:
                stable = False
        if not stable:
            record.update({"technical_status": "changed_during_scan", "technical_reasons": list(record.get("technical_reasons", [])) + ["file_metadata_changed_during_probe"], "extraction_probe_status": "skipped_unstable", "hash_status": "not_requested_unstable", "sha256": None})
        else:
            record["scan_signature"] = list(_stat_signature(after))
        return record

    def _mark_derivatives(self, records: dict[str, dict[str, Any]]) -> None:
        by_stem: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for record in records.values():
            if not record.get("present"):
                continue
            path = Path(record["relative_path"])
            stem = path.stem.casefold()
            for suffix in (".ocr", "_ocr", "-ocr", ".text", "_text", "-text"):
                if stem.endswith(suffix):
                    stem = stem[: -len(suffix)]
            by_stem[(record["root_alias"], (path.parent.as_posix() + "/" + stem).casefold())].append(record)
        for group in by_stem.values():
            extensions = {Path(record["relative_path"]).suffix.casefold() for record in group}
            if ".pdf" in extensions and extensions.intersection({".txt", ".md", ".html", ".htm"}):
                for record in group:
                    if Path(record["relative_path"]).suffix.casefold() in {".txt", ".md", ".html", ".htm"}:
                        record["possible_generated_derivative"] = True
                        record["generated_derivative_type"] = "same_stem_extraction_derivative"
                        record["technical_reasons"] = list(record.get("technical_reasons", [])) + ["same_stem_supported_document_present"]
                        if record["technical_status"] in {"ready_for_manifest", "needs_metadata_review"}:
                            record["technical_status"] = "generated_derivative"

    def _hash_if_allowed(self, record: dict[str, Any], roots_by_alias: dict[str, Path]) -> None:
        if not record.get("present") or record.get("hash_status") == "complete":
            return
        if record.get("technical_status") in {"privacy_review", "unsupported_format", "media_deferred", "software_or_cache", "corrupt_or_unreadable", "encrypted", "changed_during_scan", "generated_derivative"}:
            record["hash_status"] = "not_requested"
            return
        if int(record.get("size_bytes", 0)) > self.max_hash_bytes:
            record["hash_status"] = "deferred"
            if record.get("technical_status") in {"ready_for_manifest", "needs_metadata_review", "unprobed"}:
                record["technical_status"] = "hash_deferred"
            return
        path = roots_by_alias[record["root_alias"]] / Path(record["relative_path"])
        try:
            before = path.stat()
            digest = _full_sha256(path)
            after = path.stat()
        except OSError:
            record.update({"hash_status": "unavailable", "technical_status": "corrupt_or_unreadable", "technical_reasons": list(record.get("technical_reasons", [])) + ["sha256_failed"]})
            return
        if _stat_signature(before) != _stat_signature(after):
            record.update({"technical_status": "changed_during_scan", "technical_reasons": list(record.get("technical_reasons", [])) + ["file_metadata_changed_during_hash"], "hash_status": "not_requested_unstable", "sha256": None})
            return
        record["sha256"] = digest
        record["hash_status"] = "complete"

    def _analyze_duplicates(self, records: dict[str, dict[str, Any]], roots_by_alias: dict[str, Path]) -> None:
        for record in records.values():
            if not record.get("present"):
                continue
            if record.get("technical_status") in {"possible_duplicate", "exact_duplicate"}:
                if record.get("extraction_probe_status") == "ok":
                    record["technical_status"] = "ready_for_manifest" if record.get("metadata_status") in {"embedded_partial", "embedded_bibliographic"} else "needs_metadata_review"
                elif record.get("extraction_probe_status") in {"pending", "unavailable"}:
                    record["technical_status"] = "needs_extraction_review"
            record["duplicate_group_id"] = None
            record["duplicate_comparison_bucket"] = None
            record["duplicate_status"] = "none"
        basic: defaultdict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
        for record in records.values():
            if record.get("present") and record.get("file_kind") != "link":
                basic[(int(record.get("size_bytes", 0)), record.get("extension", ""))].append(record)
        for (size, extension), group in basic.items():
            if len(group) < 2:
                continue
            bucket_id = "size_" + hashlib.sha256(f"{size}:{extension}".encode("utf-8")).hexdigest()[:16]
            for record in group:
                record["duplicate_comparison_bucket"] = bucket_id
            quick_groups: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
            for record in group:
                if record.get("quick_fingerprint"):
                    quick_groups[record["quick_fingerprint"]].append(record)
            for quick_group in quick_groups.values():
                if len(quick_group) > 1:
                    for record in quick_group:
                        self._hash_if_allowed(record, roots_by_alias)
        eligible = [record for record in records.values() if record.get("present") and record.get("technical_status") in {"ready_for_manifest", "needs_metadata_review", "unprobed"} and not record.get("possible_private_or_unpublished") and not record.get("possible_generated_derivative") and not record.get("code_repository")]
        eligible.sort(key=lambda item: (item.get("size_bytes", 0), item.get("root_alias", ""), item.get("relative_path", "").casefold()))
        hash_budget = min(len(eligible), max(self.candidate_limit * 4, 2000))
        for record in eligible[:hash_budget]:
            self._hash_if_allowed(record, roots_by_alias)
        by_hash: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records.values():
            if record.get("present") and record.get("hash_status") == "complete" and record.get("sha256"):
                by_hash[record["sha256"]].append(record)
        for digest, group in by_hash.items():
            if len(group) > 1:
                exact_id = "exact_" + digest[:20]
                for record in group:
                    record["duplicate_group_id"] = exact_id
                    record["duplicate_status"] = "exact_duplicate"
        for group in basic.values():
            quick_groups: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
            for record in group:
                if record.get("quick_fingerprint"):
                    quick_groups[record["quick_fingerprint"]].append(record)
            for quick_fingerprint, quick_group in quick_groups.items():
                if len(quick_group) < 2:
                    continue
                pending = [record for record in quick_group if record.get("hash_status") != "complete" or not record.get("sha256")]
                if pending:
                    possible_id = "possible_" + hashlib.sha256(quick_fingerprint.encode("utf-8")).hexdigest()[:20]
                    for record in pending:
                        if record.get("duplicate_status") == "none":
                            record["duplicate_group_id"] = possible_id
                            record["duplicate_status"] = "possible_duplicate"

    @staticmethod
    def _candidate_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
        return (0 if record.get("file_kind") in {"document", "zotero_storage"} else 9, 0 if record.get("metadata_status") == "embedded_partial" else 1, int(record.get("size_bytes", 0)), record.get("root_alias", ""), record.get("relative_path", "").casefold())

    @staticmethod
    def _metadata_ready(record: dict[str, Any]) -> tuple[bool, list[str]]:
        candidates = record.get("metadata_candidates") or {}
        provenance = record.get("metadata_provenance") or {}
        reasons = []
        title = candidates.get("title")
        title_provenance = provenance.get("title") if isinstance(provenance, dict) else None
        if not isinstance(title, str) or not title.strip() or title_provenance not in {"embedded_bibliographic", "zotero_mapped", "manually_verified"}:
            reasons.append("title_missing_or_unverified")
        source_type = record.get("source_type_candidate")
        if not isinstance(source_type, str) or source_type in {"", "unknown", "document"}:
            reasons.append("source_type_missing_or_generic")
        if source_type in {"book", "journal_article"}:
            authors = candidates.get("authors") or candidates.get("editors")
            # Read the plural key first; keep the legacy singular key only for
            # records written before the EPUB normalization.
            author_provenance = provenance.get("authors") or provenance.get("author") if isinstance(provenance, dict) else None
            if not authors or author_provenance not in {"embedded_bibliographic", "zotero_mapped", "manually_verified"}:
                reasons.append("author_or_editor_missing_or_unverified")
        if any(value == "embedded_file_creator_unverified" for value in provenance.values()) if isinstance(provenance, dict) else False:
            if not candidates.get("authors") and not candidates.get("editors"):
                reasons.append("file_creator_not_an_author")
        return not reasons, reasons

    @classmethod
    def _readiness(cls, record: dict[str, Any]) -> dict[str, bool]:
        """Five-level catalog readiness; dry-run probes never create search evidence."""
        ingest_ready = bool(
            record.get("present")
            and record.get("extraction_probe_status") == "ok"
            and not record.get("possible_private_or_unpublished")
            and not record.get("possible_generated_derivative")
            and not record.get("ocr_page_fragment")
            and not record.get("code_repository")
            and not record.get("repository_document")
        )
        metadata_ready, _ = cls._metadata_ready(record)
        return {
            "ingest_ready": ingest_ready,
            "search_ready": False,
            "citation_ready": bool(ingest_ready and metadata_ready),
            "evidence_ready": False,
            "report_ready": False,
        }

    @classmethod
    def _ready_candidate(cls, record: dict[str, Any]) -> tuple[bool, list[str]]:
        reasons = []
        if not record.get("present"):
            reasons.append("not_present")
        if record.get("technical_status") not in {"ready_for_manifest", "needs_metadata_review"}:
            reasons.append("technical_probe_not_ready")
        if record.get("hash_status") != "complete":
            reasons.append("complete_sha256_required")
        if record.get("duplicate_status") != "none":
            reasons.append("duplicate_review_required")
        if record.get("possible_private_or_unpublished") or record.get("privacy_status") == "review_required":
            reasons.append("privacy_review_required")
        if record.get("code_repository") or record.get("repository_document"):
            reasons.append("code_repository_or_project_document")
        if record.get("possible_generated_derivative") or record.get("ocr_page_fragment"):
            reasons.append("generated_derivative_or_ocr_fragment")
        if record.get("extension") == ".pdf" and record.get("ocr_status") != "confirmed_text_layer":
            reasons.append("pdf_text_layer_probe_required")
        metadata_ok, metadata_reasons = cls._metadata_ready(record)
        if not metadata_ok:
            reasons.extend(metadata_reasons)
        return not reasons, reasons

    def _select_candidates(self, records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        self.ready_records: list[dict[str, Any]] = []
        self.review_records: list[dict[str, Any]] = []
        self.metadata_review_records: list[dict[str, Any]] = []
        for record in records.values():
            if not record.get("present"):
                record["selection_status"], record["selection_reasons"] = "removed", ["not_present_in_current_scan"]
                record["readiness"] = {level: False for level in self._READINESS_LEVELS}
                continue
            record["readiness"] = self._readiness(record)
            ready, reasons = self._ready_candidate(record)
            if ready:
                record["selection_status"] = "not_selected"
                record["candidate_kind"] = "ready"
                continue
            if record.get("possible_private_or_unpublished"):
                record["selection_status"] = "privacy_review"
                record["candidate_kind"] = "review"
            elif record.get("code_repository") or record.get("repository_document") or record.get("possible_generated_derivative"):
                record["selection_status"] = "excluded"
                record["candidate_kind"] = "excluded"
            elif record.get("supported_by_current_ingest") and record.get("file_kind") in {"document", "zotero_storage"}:
                record["selection_status"] = "candidate"
                record["candidate_kind"] = "review"
                record["selection_reasons"] = list(record.get("selection_reasons", [])) + reasons
                self.review_records.append(record)
                if any(reason in {"title_missing_or_unverified", "source_type_missing_or_generic", "author_or_editor_missing_or_unverified", "file_creator_not_an_author"} for reason in reasons):
                    self.metadata_review_records.append(record)
            else:
                record["selection_status"] = "excluded"
                record["candidate_kind"] = "excluded"
        eligible = [record for record in records.values() if self._ready_candidate(record)[0]]
        eligible.sort(key=self._candidate_sort_key)
        ready_selected = eligible[: self.candidate_limit]
        for record in ready_selected:
            record["selection_status"] = "candidate"
            record["candidate_kind"] = "ready"
            record["selection_reasons"] = list(record.get("selection_reasons", [])) + ["ready_minimum_metadata", "complete_sha256", "not_exact_duplicate", "no_privacy_flag"]
        remaining = max(0, self.candidate_limit - len(ready_selected))
        self.review_records.sort(key=self._candidate_sort_key)
        review_selected = self.review_records[:remaining]
        self.ready_records = ready_selected
        self.selected_review_records = review_selected
        return ready_selected + review_selected

    def _mark_removed(self, records: dict[str, dict[str, Any]], seen_keys: set[str]) -> None:
        for key, record in records.items():
            if key not in seen_keys and record.get("present", True):
                record.update({"present": False, "change_state": "removed", "technical_status": "removed_from_root", "selection_status": "removed", "technical_reasons": ["not_seen_in_current_scan"], "selection_reasons": ["not_present_in_current_scan"], "readiness": {level: False for level in self._READINESS_LEVELS}, "last_scanned_at": _now()})

    def _manifest_entry(self, record: dict[str, Any]) -> dict[str, Any]:
        candidates = record.get("metadata_candidates") or {}
        authors = candidates.get("authors") or candidates.get("editors")
        if isinstance(authors, (list, tuple)):
            creator = ", ".join(str(value) for value in authors if value)
        else:
            creator = authors or "unknown"
        source_type = record.get("source_type_candidate") or "unknown"
        return {
            "root_alias": record["root_alias"], "path": record["relative_path"],
            "title": candidates.get("title") or "unknown", "creator": creator,
            "source_type": source_type, "language": "unknown", "source_date": "unknown", "source_version": "unknown", "source_name": "unknown", "reliability_status": "unverified",
            "metadata": {"catalog_record_id": record["catalog_record_id"], "metadata_status": record["metadata_status"], "bibliographic_profile": _metadata_profile(record)},
        }

    def _dry_run_existing_ingest(self, selected: list[dict[str, Any]]) -> dict[str, Any]:
        temp_root = self.output / "temp" / "dry-run"
        temp_root.mkdir(parents=True, exist_ok=True)
        results: list[dict[str, Any]] = []
        roots_by_alias = dict(self.roots)
        grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in selected:
            grouped[record["root_alias"]].append(record)
        for alias, records in grouped.items():
            environment = temp_root / re.sub(r"[^A-Za-z0-9_.-]", "_", alias)
            settings = Settings(config_path=environment / "config.toml", root=environment, database=environment / "data" / "dry-run.db", corpus_roots=(roots_by_alias[alias],), workspace=environment / "workspace", limits=Limits())
            migrate(settings)
            for record in records:
                manifest_path = environment / f"{record['catalog_record_id']}.json"
                _atomic_write_json(manifest_path, {"files": [self._manifest_entry(record)]})
                try:
                    result = ingest_manifest(settings, Actor("local-admin", "catalog-dry-run", "user", "admin", "research-kb-catalog"), manifest_path, project_id="default", dry_run=True)
                    item = (result.get("files") or [{}])[0]
                    results.append({"catalog_record_id": record["catalog_record_id"], "status": "success", "passages": item.get("passages", 0), "deduplicated": bool(item.get("deduplicated"))})
                except Exception as exc:
                    results.append({"catalog_record_id": record["catalog_record_id"], "status": "failed", "reason": type(exc).__name__})
        success = sum(1 for result in results if result["status"] == "success")
        return {"success": success, "failed": len(results) - success, "total": len(results), "results": results}

    @staticmethod
    def _forecast_size_bucket(size_bytes: int) -> str:
        if size_bytes < 64 * 1024:
            return "0-64KiB"
        if size_bytes < 1024 * 1024:
            return "64KiB-1MiB"
        if size_bytes < 16 * 1024 * 1024:
            return "1-16MiB"
        if size_bytes < 128 * 1024 * 1024:
            return "16-128MiB"
        return "128MiB+"

    @classmethod
    def _stratified_sample(cls, records: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        if limit <= 0 or not records:
            return []
        groups: defaultdict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            parts = Path(record.get("relative_path", "")).parts
            top = parts[0] if parts else "."
            key = (record.get("extension") or "[none]", top, cls._forecast_size_bucket(int(record.get("size_bytes", 0))))
            groups[key].append(record)
        for group in groups.values():
            group.sort(key=lambda item: (item.get("root_alias", ""), item.get("relative_path", "").casefold()))
        sampled: list[dict[str, Any]] = []
        index = 0
        ordered_keys = sorted(groups)
        while len(sampled) < limit:
            added = False
            for key in ordered_keys:
                group = groups[key]
                if index < len(group):
                    sampled.append(group[index])
                    added = True
                    if len(sampled) >= limit:
                        break
            if not added:
                break
            index += 1
        return sampled

    @classmethod
    def _forecast_coverage(cls, records: list[dict[str, Any]], sampled: list[dict[str, Any]]) -> dict[str, Any]:
        def dimensions(values: list[dict[str, Any]]) -> tuple[Counter[str], Counter[str], Counter[str]]:
            extensions: Counter[str] = Counter()
            tops: Counter[str] = Counter()
            sizes: Counter[str] = Counter()
            for record in values:
                parts = Path(record.get("relative_path", "")).parts
                extensions[record.get("extension") or "[none]"] += 1
                tops[parts[0] if parts else "."] += 1
                sizes[cls._forecast_size_bucket(int(record.get("size_bytes", 0)))] += 1
            return extensions, tops, sizes
        total_ext, total_top, total_size = dimensions(records)
        sample_ext, sample_top, sample_size = dimensions(sampled)
        def coverage(total: Counter[str], sample: Counter[str]) -> dict[str, dict[str, int]]:
            return {key: {"total": total[key], "sampled": sample[key]} for key in sorted(total)}
        required_extensions = {".txt", ".md", ".docx", ".epub", ".html", ".pdf"}
        missing_extensions = sorted(extension for extension in required_extensions if not total_ext.get(extension))
        pending_pdf = any(record.get("extension") == ".pdf" and record.get("ocr_status") == "probe_pending" for record in records)
        if not sampled or missing_extensions or pending_pdf:
            confidence = "low"
        elif len(sampled) < 16:
            confidence = "low"
        elif len(sampled) < 32:
            confidence = "medium"
        else:
            confidence = "high"
        return {
            "total_records": len(records),
            "sampled_records": len(sampled),
            "by_extension": coverage(total_ext, sample_ext),
            "by_top_level_directory": coverage(total_top, sample_top),
            "by_size_bucket": coverage(total_size, sample_size),
            "missing_required_extensions": missing_extensions,
            "pending_pdf_present": pending_pdf,
            "confidence": confidence,
        }

    @staticmethod
    def _forecast_sidecar_bytes(database: Path) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += (Path(str(database) + suffix)).stat().st_size
            except OSError:
                continue
        return total

    def _measure_forecast_sample(self, sample: list[dict[str, Any]]) -> dict[str, Any]:
        temp_parent = self.output / "temp"
        temp_parent.mkdir(parents=True, exist_ok=True)
        sample_text_bytes = sum(int((record.get("probe") or {}).get("estimated_text_bytes", 0)) for record in sample)
        sample_passages = sum(int((record.get("probe") or {}).get("estimated_passages", 0)) for record in sample)
        importable = [record for record in sample if record.get("extraction_probe_status") == "ok" and record.get("technical_status") in {"ready_for_manifest", "needs_metadata_review"}]
        with tempfile.TemporaryDirectory(prefix="forecast-", dir=str(temp_parent)) as temporary:
            temp_path = Path(temporary)
            grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
            for record in importable:
                grouped[record["root_alias"]].append(record)
            fixed_bytes = 0
            post_bytes = 0
            sidecar_bytes = 0
            total_passages = 0
            successful_files = 0
            for alias, group in sorted(grouped.items()):
                safe_alias = re.sub(r"[^A-Za-z0-9_.-]", "_", alias)
                database = temp_path / f"{safe_alias}.db"
                settings = Settings(config_path=temp_path / f"{safe_alias}.toml", root=temp_path, database=database, corpus_roots=(dict(self.roots)[alias],), workspace=temp_path / "workspace", limits=Limits())
                migrate(settings)
                fixed_bytes += self._forecast_sidecar_bytes(database)
                manifest = temp_path / f"{safe_alias}.json"
                _atomic_write_json(manifest, {"files": [self._manifest_entry(record) for record in group]})
                try:
                    result = ingest_manifest(settings, Actor("local-admin", "catalog-forecast", "user", "admin", "research-kb-catalog"), manifest, project_id="default", dry_run=False)
                except Exception:
                    continue
                successful_files += sum(1 for item in result.get("files", []) if item.get("status") == "success")
                total_passages += sum(int(item.get("passages", 0)) for item in result.get("files", []))
                post_bytes += self._forecast_sidecar_bytes(database)
                sidecar_bytes += sum(max(0, self._forecast_sidecar_bytes(Path(str(database) + suffix)) - (database.stat().st_size if database.exists() else 0)) for suffix in ("-wal", "-shm"))
            if not grouped:
                alias = self.roots[0][0]
                safe_alias = re.sub(r"[^A-Za-z0-9_.-]", "_", alias)
                database = temp_path / f"{safe_alias}.db"
                settings = Settings(config_path=temp_path / f"{safe_alias}.toml", root=temp_path, database=database, corpus_roots=(dict(self.roots)[alias],), workspace=temp_path / "workspace", limits=Limits())
                migrate(settings)
                fixed_bytes = self._forecast_sidecar_bytes(database)
            return {
                "status": "measured_temporary_sample" if successful_files else ("schema_only" if fixed_bytes else "not_measured"),
                "sample_files": len(sample),
                "importable_sample_files": len(importable),
                "successful_files": successful_files,
                "sample_text_bytes": sample_text_bytes,
                "sample_passages": sample_passages,
                "measured_passages": total_passages,
                "fixed_schema_bytes": fixed_bytes,
                "post_import_bytes": post_bytes,
                "marginal_import_bytes": max(0, post_bytes - fixed_bytes) if post_bytes else 0,
                "sample_wal_sidecar_bytes": sidecar_bytes,
                "measurement_basis": "temporary_sqlite_wal_database; fixed schema separated from marginal imported data",
            }

    @staticmethod
    def _range_from_multiplier(text_bytes: int, multiplier: float, fixed_bytes: int = 0) -> dict[str, int]:
        marginal = {
            "low": int(text_bytes * multiplier * 0.75),
            "expected": int(text_bytes * multiplier),
            "high": int(text_bytes * multiplier * 1.5),
        }
        return {
            "low": fixed_bytes + marginal["low"],
            "expected": fixed_bytes + marginal["expected"],
            "high": fixed_bytes + marginal["high"],
        }

    def _native_forecast(self, records: list[dict[str, Any]], sample_limit: int) -> dict[str, Any]:
        sample = self._stratified_sample(records, sample_limit)
        measurement = self._measure_forecast_sample(sample)
        text_bytes = sum(int((record.get("probe") or {}).get("estimated_text_bytes", 0)) for record in records)
        passages = sum(int((record.get("probe") or {}).get("estimated_passages", 0)) for record in records)
        measured_text = int(measurement.get("sample_text_bytes", 0))
        measured_marginal = int(measurement.get("marginal_import_bytes", 0))
        multiplier = measured_marginal / max(1, measured_text) if measured_text and measured_marginal else 4.0
        fixed = int(measurement.get("fixed_schema_bytes", 0))
        database = self._range_from_multiplier(text_bytes, multiplier, fixed)
        wal_expected = int(measurement.get("sample_wal_sidecar_bytes", 0))
        wal = {"low": 0, "expected": wal_expected, "high": max(wal_expected, int(database["high"] * 0.25))}
        backup = {key: database[key] + wal[key] for key in ("low", "expected", "high")}
        coverage = self._forecast_coverage(records, sample)
        return {
            "record_count": len(records),
            "extractable_text_bytes": text_bytes,
            "estimated_passages": passages,
            "sample": coverage,
            "measurement": measurement,
            "fixed_schema_bytes": {"low": fixed, "expected": fixed, "high": fixed},
            "marginal_data_bytes": {key: database[key] - fixed for key in ("low", "expected", "high")},
            "database_bytes": database,
            "wal_sidecar_bytes": wal,
            "full_backup_bytes": backup,
            "database_to_text_multiplier": multiplier,
            "multiplier_basis": "measured temporary sample marginal bytes / sample extracted text bytes" if measured_marginal and measured_text else "explicit fallback 4.0x because no nonzero measured marginal sample was available",
            "confidence": coverage["confidence"] if measured_marginal else "low",
        }

    def _ocr_forecast(self, records: list[dict[str, Any]], multiplier: float, fixed_bytes: int) -> dict[str, Any]:
        statuses = Counter(record.get("ocr_status", "not_applicable") for record in records if record.get("extension") == ".pdf")
        confirmed = [record for record in records if record.get("extension") == ".pdf" and record.get("ocr_status") == "confirmed_needs_ocr"]
        pending = [record for record in records if record.get("extension") == ".pdf" and record.get("ocr_status") == "probe_pending"]
        policy = self.policy["forecast"]
        confirmed_pages = sum(int((record.get("probe") or {}).get("pages") or 0) for record in confirmed)
        pending_bytes = sum(int(record.get("size_bytes", 0)) for record in pending)
        pending_pages = {
            "low": int(pending_bytes / max(1, int(policy["unknown_ocr_bytes_per_page_high"]))),
            "expected": int(pending_bytes / max(1, int(policy["unknown_ocr_bytes_per_page_expected"]))),
            "high": int(pending_bytes / max(1, int(policy["unknown_ocr_bytes_per_page_low"]))),
        }
        pages = {key: confirmed_pages + pending_pages[key] for key in ("low", "expected", "high")}
        chars = {
            "low": pages["low"] * int(policy["unknown_ocr_chars_per_page_low"]) * 2,
            "expected": pages["expected"] * int(policy["unknown_ocr_chars_per_page_expected"]) * 2,
            "high": pages["high"] * int(policy["unknown_ocr_chars_per_page_high"]) * 2,
        }
        database = {
            "low": fixed_bytes + int(chars["low"] * multiplier * 0.75),
            "expected": fixed_bytes + int(chars["expected"] * multiplier),
            "high": fixed_bytes + int(chars["high"] * multiplier * 1.5),
        }
        wal = {"low": 0, "expected": 0, "high": int(database["high"] * 0.25)}
        backup = {key: database[key] + wal[key] for key in ("low", "expected", "high")}
        return {
            "pdf_status_counts": dict(sorted(statuses.items())),
            "confirmed_needs_ocr_files": len(confirmed),
            "probe_pending_files": len(pending),
            "encrypted_files": statuses.get("encrypted", 0),
            "corrupt_files": statuses.get("corrupt", 0),
            "confirmed_needs_ocr_pages": confirmed_pages,
            "pending_pdf_bytes": pending_bytes,
            "estimated_pages": pages,
            "estimated_pages_confidence": "low" if pending else "medium" if confirmed else "high",
            "estimated_pure_text_bytes": chars,
            "database_bytes": database,
            "wal_sidecar_bytes": wal,
            "full_backup_bytes": backup,
            "unknown_pending_page_range_is_not_zero": bool(pending),
        }

    def _forecast(self, records: dict[str, dict[str, Any]], selected: list[dict[str, Any]]) -> dict[str, Any]:
        current = [record for record in records.values() if record.get("present")]
        full_native = [
            record for record in current
            if record.get("supported_by_current_ingest")
            and not record.get("possible_private_or_unpublished")
            and not record.get("code_repository")
            and not record.get("repository_document")
            and not record.get("possible_generated_derivative")
        ]
        first_batch = [record for record in selected if record.get("candidate_kind") in {"ready", "review"}]
        first_forecast = self._native_forecast(first_batch, int(self.policy["forecast"]["first_batch_sample_size"]))
        full_forecast = self._native_forecast(full_native, int(self.policy["forecast"]["full_corpus_sample_size"]))
        multiplier = float(full_forecast.get("database_to_text_multiplier", 4.0))
        ocr = self._ocr_forecast(full_native, multiplier, int(full_forecast.get("fixed_schema_bytes", {}).get("expected", 0)))
        derivative = {
            "low": ocr["database_bytes"]["low"] + int(ocr["estimated_pure_text_bytes"]["low"] * 0.5),
            "expected": ocr["database_bytes"]["expected"] + ocr["estimated_pure_text_bytes"]["expected"],
            "high": ocr["database_bytes"]["high"] + int(ocr["estimated_pure_text_bytes"]["high"] * 2),
        }
        catalog_bytes = sum(path.stat().st_size for path in self.output.glob("*.jsonl") if path.is_file())
        return {
            "forecast_version": 2,
            "catalog_only": {"measured_catalog_jsonl_bytes": catalog_bytes, "low": catalog_bytes, "expected": catalog_bytes, "high": catalog_bytes},
            "first_batch_forecast": first_forecast,
            "full_native_corpus_forecast": full_forecast,
            "native_text_ingest": first_forecast,
            "ocr_scenario": ocr,
            "ocr_derivative_scenario": {"database_plus_sidecars_bytes": derivative, "sidecar_assumption": {"low": "0.5x pure OCR text", "expected": "1.0x pure OCR text", "high": "2.0x pure OCR text"}},
            "pdf_probe_summary": {"all_current_pdf_count": sum(1 for record in current if record.get("extension") == ".pdf"), "status_counts": dict(sorted(Counter(record.get("pdf_probe_status", "not_applicable") for record in current if record.get("extension") == ".pdf").items()))},
            "measurement": {"first_batch": first_forecast["measurement"], "full_native_corpus": full_forecast["measurement"]},
            "assumptions": [
                "Forecasts are stratified by extension, top-level directory, and size bucket; samples are deterministic.",
                "Fixed schema bytes are measured before import and are not multiplied by document count; marginal bytes are forecast from imported sample data.",
                "SQLite WAL sidecars and a full-backup reservation are reported separately; no 63x fixed overhead is applied.",
                "PDF probe_pending files contribute an explicit unknown page range derived from bounded policy bytes-per-page assumptions; they are not counted as zero.",
                "No OCR or network lookup was executed.",
            ],
            "recommendations": {
                "first_batch_reserve_backup_bytes": first_forecast["full_backup_bytes"]["high"],
                "full_native_reserve_backup_bytes": full_forecast["full_backup_bytes"]["high"],
                "reserve_pure_text_ocr_bytes": ocr["full_backup_bytes"]["high"],
                "reserve_ocr_derivative_bytes": derivative["high"] + ocr["full_backup_bytes"]["high"],
                "lightweight_boundary": "Pure OCR text can remain lightweight; retaining hOCR/ALTO/page derivatives materially increases storage and complexity.",
            },
        }

    def _summary(self, ordered: list[dict[str, Any]], selected: list[dict[str, Any]], dry_run: dict[str, Any], forecast: dict[str, Any], scan_counts: dict[str, Any], catalog_bytes: int) -> dict[str, Any]:
        extensions: Counter[str] = Counter()
        kinds: Counter[str] = Counter()
        statuses: Counter[str] = Counter()
        duplicate_statuses: Counter[str] = Counter()
        pdf_statuses: Counter[str] = Counter()
        roots_summary: defaultdict[str, dict[str, Any]] = defaultdict(lambda: {"file_count": 0, "total_size_bytes": 0, "extensions": Counter(), "top_level_directories": Counter()})
        current = [record for record in ordered if record.get("present")]
        for record in current:
            extensions[record.get("extension", "")] += 1
            kinds[record.get("file_kind", "unknown")] += 1
            statuses[record.get("technical_status", "unknown")] += 1
            duplicate_statuses[record.get("duplicate_status", "none")] += 1
            if record.get("extension") == ".pdf":
                pdf_statuses[record.get("ocr_status", "unknown")] += 1
            root = roots_summary[record["root_alias"]]
            root["file_count"] += 1
            root["total_size_bytes"] += int(record.get("size_bytes", 0))
            root["extensions"][record.get("extension", "")] += 1
            top = Path(record["relative_path"]).parts[0] if Path(record["relative_path"]).parts else "."
            root["top_level_directories"][top] += 1
        exact_ids = {record.get("duplicate_group_id") for record in current if record.get("duplicate_status") == "exact_duplicate" and record.get("duplicate_group_id")}
        possible_ids = {record.get("duplicate_group_id") for record in current if record.get("duplicate_status") == "possible_duplicate" and record.get("duplicate_group_id")}
        size_ids = {record.get("duplicate_comparison_bucket") for record in current if record.get("duplicate_comparison_bucket")}
        ocr_records = [record for record in current if record.get("ocr_status") == "confirmed_needs_ocr"]
        pending_pdf = [record for record in current if record.get("extension") == ".pdf" and record.get("ocr_status") == "probe_pending"]
        changes = Counter(record.get("change_state", "unknown") for record in ordered)
        def count_status(value: str) -> int:
            return sum(1 for record in current if record.get("privacy_classification") == value)
        title_unknown = sum(1 for record in current if not (record.get("metadata_candidates") or {}).get("title"))
        source_unknown = sum(1 for record in current if record.get("source_type_candidate") in {None, "", "unknown", "document"})
        return {
            "catalog_version": 2, "scan_id": self.scan_id, "scan_started_at": self.started_at, "scan_finished_at": _now(),
            "roots": {alias: {"file_count": data["file_count"], "total_size_bytes": data["total_size_bytes"], "extensions": dict(sorted(data["extensions"].items())), "top_level_directories": dict(sorted(data["top_level_directories"].items()))} for alias, data in sorted(roots_summary.items())},
            "totals": {"file_count": len(current), "total_size_bytes": sum(int(record.get("size_bytes", 0)) for record in current), "extension_counts": dict(sorted(extensions.items())), "file_kind_counts": dict(sorted(kinds.items())), "technical_status_counts": dict(sorted(statuses.items())), "change_state_counts": dict(sorted(changes.items()))},
            "supported_count": sum(1 for record in current if record.get("supported_by_current_ingest")),
            "unsupported_count": sum(1 for record in current if not record.get("supported_by_current_ingest")),
            "media_count": sum(1 for record in current if record.get("file_kind") == "media"),
            "software_cache_count": sum(1 for record in current if record.get("technical_status") == "software_or_cache"),
            "file_kind_counts": dict(sorted(kinds.items())),
            "privacy_review_count": sum(1 for record in current if record.get("possible_private_or_unpublished")),
            "personal_material_review_count": count_status("personal_material_review"),
            "discovery_collection_review_count": count_status("discovery_collection_review"),
            "code_repository_count": sum(1 for record in current if record.get("code_repository")),
            "repository_document_count": sum(1 for record in current if record.get("repository_document")),
            "generated_derivative_count": sum(1 for record in current if record.get("possible_generated_derivative")),
            "ocr_page_fragment_count": sum(1 for record in current if record.get("ocr_page_fragment")),
            "duplicate_status_counts": dict(sorted(duplicate_statuses.items())),
            "size_only_comparison_group_count": len(size_ids),
            "size_only_comparison_file_count": sum(1 for record in current if record.get("duplicate_comparison_bucket")),
            "possible_duplicate_group_count": len(possible_ids) if possible_ids else len(size_ids),
            "quick_possible_duplicate_group_count": len(possible_ids),
            "possible_duplicate_group_count_actual": len(possible_ids),
            "possible_duplicate_count_compatibility_note": "When no quick-fingerprint group exists, this legacy field falls back to size-only comparison groups; use quick_possible_duplicate_group_count or duplicate_status_counts for the independent possible-duplicate state.",
            "exact_duplicate_group_count": len(exact_ids),
            "duplicate_review_group_count": len(size_ids | possible_ids | exact_ids),
            "needs_ocr_count": len(ocr_records),
            "needs_ocr_estimated_pages": sum(int((record.get("probe") or {}).get("pages") or 0) for record in ocr_records),
            "pdf_probe_pending_count": len(pending_pdf),
            "pdf_ocr_status_counts": dict(sorted(pdf_statuses.items())),
            "pdf_pending_bytes": sum(int(record.get("size_bytes", 0)) for record in pending_pdf),
            "hash_deferred_count": sum(1 for record in current if record.get("hash_status") == "deferred"),
            "first_batch_candidate_count": len(selected),
            "first_batch_ready_count": sum(1 for record in selected if record.get("candidate_kind") == "ready"),
            "first_batch_review_count": sum(1 for record in selected if record.get("candidate_kind") == "review"),
            "first_batch_metadata_review_count": sum(1 for record in selected if record.get("candidate_kind") == "review" and any(reason in {"title_missing_or_unverified", "source_type_missing_or_generic", "author_or_editor_missing_or_unverified", "file_creator_not_an_author"} for reason in record.get("selection_reasons", []))),
            "readiness_counts": {
                level: sum(1 for record in current if (record.get("readiness") or {}).get(level))
                for level in self._READINESS_LEVELS
            },
            "ingest_ready_count": sum(1 for record in current if (record.get("readiness") or {}).get("ingest_ready")),
            "citation_ready_count": sum(1 for record in current if (record.get("readiness") or {}).get("citation_ready")),
            "unknown_ratios": {"title_unknown": title_unknown / max(1, len(current)), "source_type_unknown_or_generic": source_unknown / max(1, len(current)), "metadata_status_unknown": sum(1 for record in current if record.get("metadata_status") == "unknown") / max(1, len(current))},
            "dry_run": {key: value for key, value in dry_run.items() if key != "results"}, "catalog_actual_bytes": catalog_bytes,
            "storage_forecast": {key: forecast[key] for key in ("first_batch_forecast", "full_native_corpus_forecast", "native_text_ingest", "ocr_scenario", "ocr_derivative_scenario", "recommendations")},
            "timing": {"scan_seconds": round(time.monotonic() - self._scan_start_monotonic, 3)},
            "memory": {"measurement": "process RSS not collected by standard-library-only scanner"},
            "recovery": {"resumed_from_previous": bool(scan_counts.get("resumed_from_previous")), "processed_files": scan_counts.get("processed_files", 0), "scan_errors": dict(self.scan_errors)},
            "filesystem_note": "The scanner does not write source files or intentionally set atime/mtime. Operating-system access-time policy may still update atime; source mtime/content are verified in fixture tests.",
        }

    @staticmethod
    def _runbook() -> str:
        return """# Catalog runbook

This catalog is a read-only inventory and a dry-run candidate set. It does not assign permanent research importance or Source Role Map roles.

## Run

Use the existing human-admin CLI with explicit aliases:

```bash
research-kb catalog scan \\
  --root learning_materials=<ROOT_ONE> \\
  --root learning_materials_20=<ROOT_TWO> \\
  --output <CATALOG_ROOT> \\
  --candidate-limit 450
```

PowerShell uses the same command with a backtick at line endings. The generated `root-map.local.json` is local-only and must not be published.

## Outputs

`catalog.jsonl` contains all current and previously removed records using `root_alias` and `relative_path`; it never stores an absolute source path or source text. `first-batch-manifest.dry-run.json` is not an import approval. It was checked with the existing ingest dry-run in an isolated temporary database.

## Review before Phase 3.4B

Review technical statuses, `privacy-review.jsonl`, `first-batch-ready.jsonl`, `first-batch-review.jsonl`, `first-batch-metadata-review.jsonl`, duplicate state, PDF probe/OCR categories, dry-run failures, and both storage forecasts. Size-only buckets are comparison evidence only; quick possible and full-SHA exact states are independent. Do not infer permanent author, theory, topic, or research-role rankings from this catalog.

## Safety

Symlinks, junctions, and reparse points are not followed. A changed file is marked `changed_during_scan`. A scan can be restarted after interruption; the temporary progress file and scan state are used to recover without trusting an incomplete final catalog. No OCR or network lookup is performed.
"""

    def _write_outputs(self, records: dict[str, dict[str, Any]], selected: list[dict[str, Any]], dry_run: dict[str, Any], forecast: dict[str, Any], scan_counts: dict[str, Any]) -> dict[str, Any]:
        ordered = [records[key] for key in sorted(records, key=lambda item: item.casefold())]
        public_records = [_redact_local_paths({key: value for key, value in record.items() if key != "_record_key"}) for record in ordered]
        ready = [record for record in selected if record.get("candidate_kind") == "ready"]
        review = [record for record in selected if record.get("candidate_kind") == "review"]
        metadata_review = [record for record in review if any(reason in {"title_missing_or_unverified", "source_type_missing_or_generic", "author_or_editor_missing_or_unverified", "file_creator_not_an_author"} for reason in record.get("selection_reasons", []))]
        _atomic_write_jsonl(self.output / "catalog.jsonl", public_records)
        duplicate_groups: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        comparison_buckets: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in ordered:
            member = {"catalog_record_id": record["catalog_record_id"], "root_alias": record["root_alias"], "relative_path": record["relative_path"], "sha256": record.get("sha256")}
            if record.get("duplicate_group_id") and record.get("duplicate_status") in {"exact_duplicate", "possible_duplicate"}:
                duplicate_groups[record["duplicate_group_id"]].append(member)
            if record.get("duplicate_comparison_bucket"):
                comparison_buckets[record["duplicate_comparison_bucket"]].append(member)
        duplicate_rows = [
            {"duplicate_group_id": group_id, "duplicate_status": "exact_duplicate" if group_id.startswith("exact_") else "possible_duplicate", "member_count": len(members), "members": members}
            for group_id, members in sorted(duplicate_groups.items())
        ]
        duplicate_rows.extend(
            {"comparison_bucket_id": bucket_id, "duplicate_status": "size_only_comparison", "member_count": len(members), "members": members}
            for bucket_id, members in sorted(comparison_buckets.items())
        )
        _atomic_write_jsonl(self.output / "duplicate-groups.jsonl", duplicate_rows)
        _atomic_write_jsonl(self.output / "technical-review.jsonl", [
            {"catalog_record_id": record["catalog_record_id"], "root_alias": record["root_alias"], "relative_path": record["relative_path"], "file_kind": record["file_kind"], "technical_status": record["technical_status"], "technical_reasons": record.get("technical_reasons", []), "extraction_probe_status": record.get("extraction_probe_status"), "extraction_method_candidate": record.get("extraction_method_candidate"), "duplicate_status": record.get("duplicate_status"), "duplicate_comparison_bucket": record.get("duplicate_comparison_bucket"), "metadata_provenance": record.get("metadata_provenance", {}), "pdf_probe_status": record.get("pdf_probe_status"), "ocr_status": record.get("ocr_status"), "probe": record.get("probe", {}), "readiness": record.get("readiness", {})}
            for record in ordered
        ])
        _atomic_write_jsonl(self.output / "privacy-review.jsonl", [
            {"catalog_record_id": record["catalog_record_id"], "root_alias": record["root_alias"], "relative_path": record["relative_path"], "possible_private_or_unpublished": True, "privacy_classification": record.get("privacy_classification"), "privacy_status": record.get("privacy_status"), "selection_status": record.get("selection_status"), "reasons": record.get("selection_reasons", [])}
            for record in ordered if record.get("possible_private_or_unpublished")
        ])
        def candidate_row(record: dict[str, Any]) -> dict[str, Any]:
            return {"catalog_record_id": record["catalog_record_id"], "root_alias": record["root_alias"], "relative_path": record["relative_path"], "extension": record["extension"], "size_bytes": record["size_bytes"], "technical_status": record["technical_status"], "metadata_status": record["metadata_status"], "metadata_provenance": record.get("metadata_provenance", {}), "source_type_candidate": record.get("source_type_candidate"), "sha256": record.get("sha256"), "selection_status": record["selection_status"], "candidate_kind": record.get("candidate_kind"), "selection_reasons": record.get("selection_reasons", []), "readiness": record.get("readiness", {})}
        _atomic_write_jsonl(self.output / "first-batch-candidates.jsonl", (candidate_row(record) for record in selected))
        _atomic_write_jsonl(self.output / "first-batch-ready.jsonl", (candidate_row(record) for record in ready))
        _atomic_write_jsonl(self.output / "first-batch-review.jsonl", (candidate_row(record) for record in review))
        _atomic_write_jsonl(self.output / "first-batch-metadata-review.jsonl", (candidate_row(record) for record in metadata_review))
        _atomic_write_json(self.output / "first-batch-manifest.dry-run.json", {"manifest_version": 2, "dry_run_only": True, "selection_basis": "ready candidates are separated from metadata/technical review candidates; this is not an import approval", "files": [_redact_local_paths(self._manifest_entry(record)) for record in selected], "ready_files": [_redact_local_paths(self._manifest_entry(record)) for record in ready], "dry_run_summary": {key: value for key, value in dry_run.items() if key != "results"}})
        _atomic_write_json(self.output / "storage-forecast.json", forecast)
        published_files = [path for path in self.output.glob("*") if path.is_file() and path.name != "root-map.local.json"]
        catalog_bytes = sum(path.stat().st_size for path in published_files)
        summary = self._summary(ordered, selected, dry_run, forecast, scan_counts, catalog_bytes)
        _atomic_write_json(self.output / "summary.json", summary)
        _atomic_write_text(self.output / "CATALOG-RUNBOOK.md", self._runbook())
        _atomic_write_json(self.output / "root-map.local.json", {"root_aliases": {alias: str(path) for alias, path in self.roots}, "warning": "local-only mapping; do not publish"})
        try:
            self.partial_path.unlink()
        except FileNotFoundError:
            pass
        _atomic_write_json(self.state_path, {"scan_id": self.scan_id, "status": "complete", "started_at": self.started_at, "finished_at": _now(), "resumed_from_previous": bool(scan_counts.get("resumed_from_previous")), "processed_files": scan_counts.get("processed_files", 0), "current_files": summary["totals"]["file_count"], "removed_records": sum(1 for record in ordered if not record.get("present")), "scan_errors": dict(self.scan_errors)})
        return summary

    def scan(self, *, stop_after: int | None = None) -> dict[str, Any]:
        self._scan_start_monotonic = time.monotonic()
        roots_by_alias = dict(self.roots)
        partial_existing = _read_jsonl(self.partial_path)
        existing = dict(partial_existing)
        existing.update(_read_jsonl(self.output / "catalog.jsonl"))
        previous_state = _read_json(self.state_path, {}) or {}
        resumed = bool(partial_existing) or previous_state.get("status") in {"scanning", "interrupted"}
        state = {"scan_id": self.scan_id, "status": "scanning", "started_at": self.started_at, "resumed_from_previous": resumed, "partial_file": self.partial_path.name, "processed_files": 0}
        _atomic_write_json(self.state_path, state)
        discovered = self._discover()
        seen_keys: set[str] = set()
        processed = 0
        try:
            with self.partial_path.open("a", encoding="utf-8", newline="\n") as partial:
                for alias, relative, path, st, link_like in discovered:
                    key = _record_key(alias, relative)
                    seen_keys.add(key)
                    record = self._process_one(alias, relative, path, st, link_like, existing.get(key))
                    existing[key] = record
                    partial.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                    processed += 1
                    if processed % self.checkpoint_interval == 0:
                        partial.flush()
                        os.fsync(partial.fileno())
                        _atomic_write_json(self.state_path, {**state, "processed_files": processed, "discovered_files": len(discovered), "last_record_key": key})
                        if self.progress:
                            self.progress({"processed": processed, "total": len(discovered), "percent": round(processed * 100 / max(1, len(discovered)), 2)})
                    if stop_after is not None and processed >= stop_after:
                        raise CatalogInterrupted("catalog scan interrupted for recovery test")
                partial.flush()
                os.fsync(partial.fileno())
        except (KeyboardInterrupt, CatalogInterrupted) as exc:
            _atomic_write_json(self.state_path, {**state, "status": "interrupted", "processed_files": processed, "discovered_files": len(discovered)})
            raise CatalogInterrupted("catalog scan interrupted; rerun to resume") from exc
        self._mark_removed(existing, seen_keys)
        self._mark_derivatives(existing)
        self._analyze_duplicates(existing, roots_by_alias)
        selected = self._select_candidates(existing)
        dry_run = self._dry_run_existing_ingest(selected)
        failed_ids = {result["catalog_record_id"] for result in dry_run.get("results", []) if result.get("status") != "success"}
        if failed_ids:
            for record in selected:
                if record.get("catalog_record_id") in failed_ids:
                    record["selection_status"] = "not_selected"
                    record["selection_reasons"] = list(record.get("selection_reasons", [])) + ["existing_ingest_dry_run_failed"]
            selected = [record for record in selected if record.get("catalog_record_id") not in failed_ids]
            dry_run = self._dry_run_existing_ingest(selected)
        forecast = self._forecast(existing, selected)
        return self._write_outputs(existing, selected, dry_run, forecast, {"resumed_from_previous": resumed, "processed_files": processed})


def run_catalog_scan(root_specs: Iterable[str], output: str | Path, *, candidate_limit: int = 450, max_hash_bytes: int = _DEFAULT_MAX_HASH_BYTES, checkpoint_interval: int = 250, progress: Callable[[dict[str, Any]], None] | None = None, policy_path: str | Path | None = None) -> dict[str, Any]:
    roots = _validate_roots(root_specs)
    scanner = CatalogScanner(roots, output, candidate_limit=candidate_limit, max_hash_bytes=max_hash_bytes, checkpoint_interval=checkpoint_interval, progress=progress, policy_path=policy_path)
    summary = scanner.scan()
    return {"ok": True, "catalog_version": 2, "summary": summary, "output_files": ["catalog.jsonl", "scan-state.json", "summary.json", "duplicate-groups.jsonl", "technical-review.jsonl", "privacy-review.jsonl", "first-batch-candidates.jsonl", "first-batch-ready.jsonl", "first-batch-review.jsonl", "first-batch-metadata-review.jsonl", "first-batch-manifest.dry-run.json", "storage-forecast.json", "CATALOG-RUNBOOK.md", "root-map.local.json"]}


def parse_root_specs(values: Iterable[str]) -> list[str]:
    return list(values)
