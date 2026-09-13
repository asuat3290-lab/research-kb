from __future__ import annotations

import sqlite3
import unicodedata
from typing import Iterable


_CJK_RANGES = (
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xF900, 0xFAFF),
)


def is_cjk(character: str) -> bool:
    codepoint = ord(character)
    return any(start <= codepoint <= end for start, end in _CJK_RANGES)


def _append_token(tokens: list[str], token: str) -> None:
    value = token.strip()
    if value and value not in tokens:
        tokens.append(value)


def normalize_search_terms(text: str) -> str:
    """Return deterministic whitespace-separated ASCII/CJK search terms.

    Source text is never replaced by this representation.  Latin and numeric
    runs are case-folded and hyphenated words are split into stable terms;
    contiguous CJK runs become overlapping bigrams.
    """
    normalized = unicodedata.normalize("NFKC", str(text or "")).casefold()
    tokens: list[str] = []
    latin_buffer: list[str] = []
    cjk_buffer: list[str] = []

    def flush_latin() -> None:
        if latin_buffer:
            _append_token(tokens, "".join(latin_buffer))
            latin_buffer.clear()

    def flush_cjk() -> None:
        if not cjk_buffer:
            return
        if len(cjk_buffer) == 1:
            _append_token(tokens, cjk_buffer[0])
        else:
            for index in range(len(cjk_buffer) - 1):
                _append_token(tokens, "".join(cjk_buffer[index : index + 2]))
        cjk_buffer.clear()

    for character in normalized:
        if is_cjk(character):
            flush_latin()
            cjk_buffer.append(character)
        elif character.isalnum():
            flush_cjk()
            latin_buffer.append(character)
        else:
            flush_cjk()
            flush_latin()
    flush_cjk()
    flush_latin()
    return " ".join(tokens)


def search_terms(text: str) -> list[str]:
    normalized = normalize_search_terms(text)
    return normalized.split() if normalized else []


def fts_match_query(text: str, match_strategy: str = "all") -> str:
    if match_strategy not in {"all", "any"}:
        raise ValueError("match_strategy must be all or any")
    terms = search_terms(text)
    if not terms:
        raise ValueError("query contains no searchable terms")
    operator = " AND " if match_strategy == "all" else " OR "
    return operator.join('"' + term.replace('"', '""') + '"' for term in terms)


def excerpt_from_original(text: str, query: str, maximum: int = 700) -> str:
    """Return a bounded excerpt sliced from original, unnormalized passage text."""
    source = str(text or "")
    if len(source) <= maximum:
        return source
    normalized_source = unicodedata.normalize("NFKC", source).casefold()
    normalized_query = unicodedata.normalize("NFKC", str(query or "")).casefold().strip()
    position = normalized_source.find(normalized_query) if normalized_query else -1
    if position < 0:
        for term in search_terms(query):
            position = normalized_source.find(term)
            if position >= 0:
                break
    if position < 0:
        return source[:maximum]
    radius = max(80, (maximum - 20) // 2)
    start = max(0, position - radius)
    end = min(len(source), start + maximum)
    if end - start < maximum:
        start = max(0, end - maximum)
    excerpt = source[start:end]
    return ("…" if start else "") + excerpt + ("…" if end < len(source) else "")


def index_passage_in_connection(
    connection: sqlite3.Connection,
    *,
    passage_id: str,
    title: str,
    body: str,
) -> None:
    connection.execute(
        "INSERT INTO passages_search_fts(passage_id, title, body) VALUES (?, ?, ?)",
        (passage_id, normalize_search_terms(title), normalize_search_terms(body)),
    )


def rebuild_search_index_in_connection(connection: sqlite3.Connection) -> int:
    """Rebuild the derived FTS cache from immutable passages and documents."""
    try:
        connection.execute("DELETE FROM passages_search_fts")
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return 0
        raise
    rows = connection.execute(
        """
        SELECT p.passage_id, d.title, p.text
        FROM passages p
        JOIN documents d ON d.document_id = p.document_id
        ORDER BY p.document_id, p.ordinal
        """
    ).fetchall()
    connection.executemany(
        "INSERT INTO passages_search_fts(passage_id, title, body) VALUES (?, ?, ?)",
        (
            (row["passage_id"], normalize_search_terms(row["title"]), normalize_search_terms(row["text"]))
            for row in rows
        ),
    )
    return len(rows)