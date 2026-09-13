from __future__ import annotations

import hashlib
import html
import json
import re
import uuid
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from .config import Settings
from .db import audit, connect, transaction
from .policy import Actor, PolicyError, require_admin, resolve_corpus_file
from .search import index_passage_in_connection


SUPPORTED_EXTENSIONS = {".txt", ".md", ".html", ".htm", ".pdf", ".docx", ".epub"}
_MANIFEST_FIELDS = (
    "title",
    "creator",
    "source_type",
    "language",
    "source_date",
    "source_version",
    "source_name",
    "reliability_status",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strip_html(value: str) -> str:
    value = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    return re.sub(r"[ \t]+", " ", html.unescape(value)).strip()


def _extract_docx(path: Path) -> list[tuple[dict, str]]:
    with zipfile.ZipFile(path) as archive:
        root = ElementTree.fromstring(archive.read("word/document.xml"))
    paragraphs = []
    for paragraph in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"):
        text = "".join(
            node.text or ""
            for node in paragraph.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")
        ).strip()
        if text:
            paragraphs.append(text)
    return [({"section": 1}, "\n\n".join(paragraphs))]


def _extract_epub(path: Path) -> list[tuple[dict, str]]:
    sections = []
    with zipfile.ZipFile(path) as archive:
        names = sorted(
            name for name in archive.namelist()
            if name.lower().endswith((".html", ".htm", ".xhtml"))
        )
        for index, name in enumerate(names, start=1):
            text = _strip_html(archive.read(name).decode("utf-8", errors="replace"))
            if text:
                sections.append(({"section": index, "member": name}, text))
    return sections


def _extract_pdf(path: Path) -> list[tuple[dict, str]]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError("PDF import requires the optional 'pdf' dependency") from exc
    reader = PdfReader(str(path))
    sections = []
    for index, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        if text.strip():
            sections.append(({"page": index}, text))
    return sections


def extract_sections(path: Path) -> list[tuple[dict, str]]:
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"unsupported source type: {suffix}")
    if suffix in {".txt", ".md"}:
        return [({"section": 1}, path.read_text(encoding="utf-8", errors="replace"))]
    if suffix in {".html", ".htm"}:
        return [({"section": 1}, _strip_html(path.read_text(encoding="utf-8", errors="replace")))]
    if suffix == ".docx":
        return _extract_docx(path)
    if suffix == ".epub":
        return _extract_epub(path)
    return _extract_pdf(path)


def _chunks(text: str, maximum: int = 2400) -> list[tuple[int, int, str]]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return []
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", normalized) if part.strip()]
    output: list[tuple[int, int, str]] = []
    buffer = ""
    start = 0
    cursor = 0
    for paragraph in paragraphs:
        found = normalized.find(paragraph, cursor)
        found = cursor if found < 0 else found
        if buffer and len(buffer) + len(paragraph) + 2 > maximum:
            output.append((start, start + len(buffer), buffer))
            buffer = ""
        if not buffer:
            start = found
        while len(paragraph) > maximum:
            if buffer:
                output.append((start, start + len(buffer), buffer))
                buffer = ""
            output.append((found, found + maximum, paragraph[:maximum]))
            paragraph = paragraph[maximum:]
            found += maximum
            start = found
        buffer = f"{buffer}\n\n{paragraph}".strip() if buffer else paragraph
        cursor = found + len(paragraph)
    if buffer:
        output.append((start, start + len(buffer), buffer))
    return output


def _normalize_manifest_value(entry: dict, key: str, default: str) -> str:
    value = entry.get(key)
    if value is None or not str(value).strip():
        return default
    return str(value).strip()


def _load_manifest(path: str | Path) -> list[dict]:
    manifest_path = Path(path).expanduser().resolve(strict=True)
    if not manifest_path.is_file():
        raise PolicyError("manifest must be a regular file")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError("manifest is not valid UTF-8 JSON") from exc
    entries = payload.get("files") if isinstance(payload, dict) else payload
    if not isinstance(entries, list) or not entries:
        raise PolicyError("manifest must contain a non-empty files list")
    if len(entries) > 1000:
        raise PolicyError("manifest contains too many files")
    if any(not isinstance(entry, dict) for entry in entries):
        raise PolicyError("manifest entries must be objects")
    return entries


def _resolve_manifest_source(settings: Settings, supplied: str | Path) -> Path:
    candidate = Path(supplied).expanduser()
    if candidate.is_absolute():
        return resolve_corpus_file(settings, candidate)
    matches = []
    for root in settings.corpus_roots:
        possible = root / candidate
        if possible.exists():
            matches.append(possible)
    if len(matches) != 1:
        if not matches:
            raise PolicyError("manifest source does not resolve inside a configured corpus root")
        raise PolicyError("manifest source is ambiguous across configured corpus roots")
    return resolve_corpus_file(settings, matches[0])


def _manifest_record(settings: Settings, entry: dict) -> tuple[Path, dict]:
    supplied = entry.get("path")
    if not supplied or not isinstance(supplied, str):
        raise PolicyError("manifest entry requires a string path")
    source = _resolve_manifest_source(settings, supplied)
    metadata = {
        key: _normalize_manifest_value(
            entry,
            key,
            "unverified" if key == "reliability_status" else "unknown",
        )
        for key in _MANIFEST_FIELDS
    }
    extra = entry.get("metadata", {})
    if not isinstance(extra, dict):
        raise PolicyError("manifest metadata must be an object")
    metadata["metadata"] = extra
    return source, metadata


def _extract_sections_safe(source: Path) -> list[tuple[dict, str]]:
    try:
        sections = extract_sections(source)
    except Exception as exc:
        raise PolicyError("source extraction failed") from exc
    if not any(_chunks(text) for _, text in sections):
        raise PolicyError("source contains no extractable text")
    return sections


def _preview_file(settings: Settings, source: Path) -> dict:
    raw = source.read_bytes()
    content_hash = _sha256(raw)
    sections = _extract_sections_safe(source)
    passage_count = sum(len(_chunks(text)) for _, text in sections)
    with connect(settings, read_only=True) as connection:
        existing = connection.execute(
            "SELECT document_id FROM documents WHERE content_hash = ?", (content_hash,)
        ).fetchone()
    return {
        "source_name": source.name,
        "content_hash": content_hash,
        "document_id": f"doc_{content_hash[:20]}",
        "deduplicated": bool(existing),
        "passages": 0 if existing else passage_count,
    }


def ingest_file(
    settings: Settings,
    actor: Actor,
    path: str | Path,
    *,
    project_id: str,
    title: str | None,
    creator: str | None,
    source_type: str = "unknown",
    language: str = "unknown",
    source_date: str | None = None,
    source_version: str | None = None,
    source_name: str | None = None,
    reliability_status: str = "unverified",
    metadata: dict | None = None,
) -> dict:
    require_admin(actor)
    source = resolve_corpus_file(settings, path)
    raw = source.read_bytes()
    content_hash = _sha256(raw)
    document_id = f"doc_{content_hash[:20]}"
    sections = _extract_sections_safe(source)
    title = str(title or "unknown").strip() or "unknown"
    creator = str(creator).strip() if creator else "unknown"
    source_type = str(source_type or "unknown").strip() or "unknown"
    language = str(language or "unknown").strip() or "unknown"
    source_name = str(source_name or "unknown").strip() or "unknown"
    source_date = str(source_date).strip() if source_date else None
    source_version = str(source_version or "unknown").strip() or "unknown"
    reliability_status = str(reliability_status or "unverified").strip() or "unverified"
    if reliability_status not in {"unknown", "unverified", "reviewed", "authoritative"}:
        raise PolicyError("invalid reliability_status")
    with transaction(settings) as connection:
        project = connection.execute(
            "SELECT project_id FROM projects WHERE project_id = ? AND status = 'active'",
            (project_id,),
        ).fetchone()
        if not project:
            raise PolicyError(f"active project not found: {project_id}")
        existing = connection.execute(
            "SELECT document_id FROM documents WHERE content_hash = ?", (content_hash,)
        ).fetchone()
        if existing:
            connection.execute(
                "INSERT OR IGNORE INTO project_sources(project_id, document_id, added_at) VALUES (?, ?, datetime('now'))",
                (project_id, existing["document_id"]),
            )
            result = {"document_id": existing["document_id"], "deduplicated": True, "passages": 0}
            audit(
                connection, actor_id=actor.actor_id, actor_kind=actor.actor_kind,
                session_id=actor.session_id, project_id=project_id, operation="ingest_file",
                parameters={"source_name": source_name, "source_type": source_type}, result=result,
            )
            return result

        connection.execute(
            """
            INSERT INTO documents(
                document_id, content_hash, title, creator, source_type, language,
                source_date, source_version, source_name, source_uri,
                reliability_status, verification_status, ingestion_method,
                metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?, ?, datetime('now'))
            """,
            (
                document_id, content_hash, title, creator, source_type, language,
                source_date, source_version, source_name, str(source), reliability_status,
                f"extract:{source.suffix.lower()[1:]}",
                json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True),
            ),
        )
        ordinal = 0
        for section_location, text in sections:
            for char_start, char_end, chunk in _chunks(text):
                ordinal += 1
                text_hash = _sha256(chunk.encode("utf-8"))
                passage_id = f"psg_{_sha256(f'{content_hash}:{ordinal}:{text_hash}'.encode())[:20]}"
                location = {**section_location, "char_start": char_start, "char_end": char_end}
                connection.execute(
                    """
                    INSERT INTO passages(
                        passage_id, document_id, ordinal, location_json, text,
                        text_hash, char_start, char_end, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    """,
                    (
                        passage_id, document_id, ordinal,
                        json.dumps(location, ensure_ascii=False, sort_keys=True),
                        chunk, text_hash, char_start, char_end,
                    ),
                )
                index_passage_in_connection(
                    connection, passage_id=passage_id, title=title, body=chunk
                )
        connection.execute(
            "INSERT INTO project_sources(project_id, document_id, added_at) VALUES (?, ?, datetime('now'))",
            (project_id, document_id),
        )
        result = {"document_id": document_id, "deduplicated": False, "passages": ordinal}
        audit(
            connection, actor_id=actor.actor_id, actor_kind=actor.actor_kind,
            session_id=actor.session_id, project_id=project_id, operation="ingest_file",
            parameters={"source_name": source_name, "source_type": source_type}, result=result,
        )
        return result


def ingest_manifest(
    settings: Settings,
    actor: Actor,
    manifest_path: str | Path,
    *,
    project_id: str,
    dry_run: bool = False,
) -> dict:
    require_admin(actor)
    entries = _load_manifest(manifest_path)
    results = []
    for entry in entries:
        source, metadata = _manifest_record(settings, entry)
        if dry_run:
            result = _preview_file(settings, source)
            result.update({"title": metadata["title"], "source_type": metadata["source_type"]})
        else:
            result = ingest_file(
                settings,
                actor,
                source,
                project_id=project_id,
                title=metadata["title"],
                creator=metadata["creator"],
                source_type=metadata["source_type"],
                language=metadata["language"],
                source_date=None if metadata["source_date"] == "unknown" else metadata["source_date"],
                source_version=metadata["source_version"],
                source_name=metadata["source_name"],
                reliability_status=metadata["reliability_status"],
                metadata=metadata["metadata"],
            )
        results.append({"path": str(entry["path"]), **result})
    return {"project_id": project_id, "dry_run": dry_run, "count": len(results), "files": results}