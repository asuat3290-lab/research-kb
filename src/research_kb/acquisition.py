from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable


WORKER_NAME = "research-kb-literature-acquisition"
WORKER_VERSION = "0.1.0"
STAGING_SCHEMA_VERSION = 1
SEP_BASE = "https://plato.stanford.edu/entries/"
OPENALEX_WORKS_URL = "https://api.openalex.org/works"
UNPAYWALL_URL = "https://api.unpaywall.org/v2/"
CROSSREF_WORKS_URL = "https://api.crossref.org/works"
SEP_MAX_BYTES = 8 * 1024 * 1024
JSON_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
PDF_MAGIC = b"%PDF-"
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_SECONDS = 2.0
DEFAULT_MAX_BACKOFF_SECONDS = 8.0
MAX_CONSECUTIVE_RATE_LIMITS = 3
_DOI_RE = re.compile(r"\b10\.\d{4,9}/[^\s,;&<>\"'“”]+", re.IGNORECASE)
_YEAR_RE = re.compile(r"(?<![\d])(1[89]\d{2}|20\d{2})(?![\d])")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_QUOTED_TITLE_RE = re.compile(r"[“\"]([^”\"]{4,})[”\"]")
_SEP_ENTRY_PATH_RE = re.compile(r"entries/([^/?#]+)")
_SEP_RELATIVE_SLUG_RE = re.compile(r"\.\.?/([A-Za-z0-9][A-Za-z0-9-]*)/?$")
_SEP_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")
_FRONT_MATTER_RE = re.compile(
    r"^(contents|frontmatter|backmatter|index|preface|introduction|"
    r"acknowledgements?|editorial board|title page|dedication|about the (author|book))$"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _clean_space(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _extract_doi(text: str) -> str | None:
    match = _DOI_RE.search(text)
    if not match:
        return None
    return _clean_space(match.group(0)).rstrip(".,;:()[]{}")


def _normalize_doi(doi: str | None) -> str | None:
    if not doi:
        return None
    value = _clean_space(doi).rstrip(".,;:()[]{}")
    value = re.sub(r"^doi:\s*", "", value, flags=re.IGNORECASE)
    value = re.sub(r"^https?://(dx\.)?doi\.org/", "", value, flags=re.IGNORECASE)
    return value or None


def _extract_year(text: str) -> int | None:
    match = _YEAR_RE.search(text)
    return int(match.group(1)) if match else None


def _extract_urls(text: str) -> list[str]:
    return [url.rstrip(".,;:)]}") for url in _URL_RE.findall(text)]


def _extract_title(citation: str, em_title: str | None) -> str | None:
    quoted = [part.strip() for part in _QUOTED_TITLE_RE.findall(citation)]
    if quoted:
        return quoted[0].rstrip(",.;:")
    if em_title:
        return em_title.rstrip(",.;:")
    return None


def _normalize_text(value: Any) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _token_coverage(candidate: str, target: str) -> float:
    left = _normalize_text(candidate).split()
    right = set(_normalize_text(target).split())
    if not left:
        return 0.0
    return len(set(left) & right) / len(left)


def _is_substantive_work(record: dict[str, Any]) -> bool:
    title = _normalize_text(record.get("title"))
    if _FRONT_MATTER_RE.fullmatch(title):
        return False
    doi = (record.get("doi") or "").lower()
    if re.search(r"-(toc|fm|bm|idx|index)$", doi):
        return False
    return True


class _SepEntryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.pubinfo_parts: list[str] = []
        self.bibliography: list[dict[str, Any]] = []
        self.related: list[dict[str, str]] = []
        self._in_h1 = False
        self._in_pubinfo = False
        self._pubinfo_depth = 0
        self._in_bib = False
        self._bib_depth = 0
        self._in_related = False
        self._related_depth = 0
        self._heading_parts: list[str] = []
        self._in_heading = False
        self._heading = ""
        self._li_parts: list[str] = []
        self._li_em: list[str] = []
        self._in_li = False
        self._em_depth = 0
        self._rel_href: str | None = None
        self._rel_link_parts: list[str] = []

    @property
    def title(self) -> str:
        return _clean_space(" ".join(self.title_parts))

    @property
    def pubinfo(self) -> str:
        return _clean_space(" ".join(self.pubinfo_parts))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "div":
            div_id = attrs_dict.get("id")
            if div_id == "pubinfo":
                self._in_pubinfo = True
                self._pubinfo_depth = 1
            elif self._in_pubinfo:
                self._pubinfo_depth += 1
            elif div_id == "bibliography":
                self._in_bib = True
                self._bib_depth = 1
            elif self._in_bib:
                self._bib_depth += 1
            elif div_id == "related-entries":
                self._in_related = True
                self._related_depth = 1
            elif self._in_related:
                self._related_depth += 1
        elif tag == "h1":
            self._in_h1 = True
        elif self._in_bib and tag in ("h2", "h3", "h4"):
            self._in_heading = True
            self._heading_parts = []
        elif self._in_bib and tag == "li":
            self._in_li = True
            self._li_parts = []
            self._li_em = []
            self._em_depth = 0
        elif self._in_li and tag == "em":
            self._em_depth += 1
        elif self._in_related and tag == "a":
            self._rel_href = attrs_dict.get("href")
            self._rel_link_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_h1:
            self.title_parts.append(data)
        if self._in_pubinfo:
            self.pubinfo_parts.append(data)
        if self._in_heading:
            self._heading_parts.append(data)
        if self._in_li:
            self._li_parts.append(data)
            if self._em_depth > 0:
                self._li_em.append(data)
        if self._in_related and self._rel_href is not None:
            self._rel_link_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "div":
            if self._in_pubinfo:
                self._pubinfo_depth -= 1
                if self._pubinfo_depth == 0:
                    self._in_pubinfo = False
            elif self._in_bib:
                self._bib_depth -= 1
                if self._bib_depth == 0:
                    self._in_bib = False
            elif self._in_related:
                self._related_depth -= 1
                if self._related_depth == 0:
                    self._in_related = False
        elif tag == "h1":
            self._in_h1 = False
        elif self._in_bib and tag in ("h2", "h3", "h4"):
            self._heading = _clean_space("".join(self._heading_parts))
            self._in_heading = False
        elif self._in_li and tag == "li":
            citation = _clean_space("".join(self._li_parts))
            em_title = _clean_space(" ".join(self._li_em)) or None
            if citation:
                self.bibliography.append(
                    {
                        "section": self._heading,
                        "citation": citation,
                        "em_title": em_title,
                    }
                )
            self._in_li = False
            self._em_depth = 0
        elif self._in_li and tag == "em" and self._em_depth > 0:
            self._em_depth -= 1
        elif self._in_related and tag == "a":
            if self._rel_href:
                self.related.append(
                    {
                        "url": self._rel_href,
                        "label": _clean_space("".join(self._rel_link_parts)),
                    }
                )
            self._rel_href = None


def _sep_slug_from_url(url: str) -> str | None:
    match = _SEP_ENTRY_PATH_RE.search(url or "")
    if match:
        return match.group(1)
    match = _SEP_RELATIVE_SLUG_RE.search(url or "")
    return match.group(1) if match else None


def _sep_slug_url(value: str) -> tuple[str, str]:
    value = value.strip()
    if value.startswith(("http://", "https://", "/")):
        slug = _sep_slug_from_url(value)
        if not slug:
            raise ValueError(f"invalid SEP entry URL: {value}")
        return slug, f"{SEP_BASE}{slug}/"
    if not _SEP_SLUG_RE.fullmatch(value):
        raise ValueError(f"invalid SEP entry slug: {value}")
    return value, f"{SEP_BASE}{value}/"


def _request(
    url: str,
    user_agent: str,
    accept: str,
    context: ssl.SSLContext | None = None,
) -> urllib.request.Request:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": accept,
        },
    )
    if context is not None:
        request.context = context
    return request


def _fetch_bytes(
    url: str,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
    max_bytes: int | None = None,
    retries: int = DEFAULT_MAX_RETRIES,
) -> bytes:
    for attempt in range(retries + 1):
        request = _request(url, user_agent, "*/*")
        try:
            with urlopen(request, timeout=timeout) as response:
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if max_bytes is not None and total > max_bytes:
                        raise ValueError(f"response exceeds {max_bytes} bytes")
                    chunks.append(chunk)
            return b"".join(chunks)
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRY_STATUS_CODES or attempt >= retries:
                raise
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            try:
                wait = min(float(retry_after), DEFAULT_MAX_BACKOFF_SECONDS)
            except (TypeError, ValueError):
                wait = min(
                    DEFAULT_BACKOFF_SECONDS * (2**attempt),
                    DEFAULT_MAX_BACKOFF_SECONDS,
                )
            time.sleep(wait)
    raise RuntimeError("unreachable")


def _fetch_json(
    url: str,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
    delay: float = 0.0,
) -> tuple[Any | None, str | None]:
    if delay > 0:
        time.sleep(delay)
    try:
        data = _fetch_bytes(
            url, timeout, user_agent, urlopen, max_bytes=JSON_MAX_BYTES
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc} @ {url[:200]}"
    try:
        return json.loads(data.decode("utf-8", errors="replace")), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"


def fetch_sep_entry(
    url: str,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = _fetch_bytes(url, timeout, user_agent, urlopen, max_bytes=SEP_MAX_BYTES)
    except Exception as exc:
        return None, f"fetch failed: {exc}"
    text = data.decode("utf-8", errors="replace")
    if "<title>Document Not Found</title>" in text or len(data) < 500:
        return None, "SEP returned document not found"
    parser = _SepEntryParser()
    parser.feed(text)
    parser.close()
    bibliography = parser.bibliography
    for record in bibliography:
        citation = record["citation"]
        years = [int(year) for year in _YEAR_RE.findall(citation)]
        record["years"] = years
        record["year"] = years[0] if years else None
        record["doi"] = _extract_doi(citation)
        record["urls"] = _extract_urls(citation)
        record["title_candidate"] = _extract_title(citation, record.get("em_title"))
    related = [
        {
            "slug": slug,
            "url": rel["url"],
            "label": rel["label"],
        }
        for rel in parser.related
        if (slug := _sep_slug_from_url(rel["url"]))
    ]
    return {
        "title": parser.title,
        "pubinfo": parser.pubinfo,
        "url": url,
        "bibliography": bibliography,
        "related_entries": related,
        "content_hash": _sha256_bytes(data),
        "bytes": len(data),
    }, None


def _work_record(work: dict[str, Any]) -> dict[str, Any]:
    title = work.get("title") or work.get("display_name") or ""
    authors: list[str] = []
    for authorship in work.get("authorships") or []:
        author = authorship.get("author") or {}
        name = author.get("display_name")
        if name:
            authors.append(name)
    primary = work.get("primary_location") or {}
    source = primary.get("source") or {}
    best = work.get("best_oa_location") or {}
    return {
        "openalex_id": work.get("id"),
        "title": title,
        "authors": authors,
        "year": work.get("publication_year"),
        "venue": source.get("display_name"),
        "doi": work.get("doi"),
        "is_oa": bool((work.get("open_access") or {}).get("is_oa")),
        "pdf_url": best.get("pdf_url") or primary.get("pdf_url"),
        "landing_url": best.get("landing_page_url") or primary.get("landing_page_url"),
    }


def _crossref_work_record(work: dict[str, Any]) -> dict[str, Any]:
    title = work.get("title") or []
    title = title[0] if isinstance(title, list) and title else ""
    authors: list[str] = []
    for author in work.get("author") or []:
        if not isinstance(author, dict):
            continue
        given = (author.get("given") or "").strip()
        family = (author.get("family") or "").strip()
        if given or family:
            authors.append(f"{given} {family}".strip())
    year: int | None = None
    issued = work.get("issued") or {}
    date_parts = issued.get("date-parts") or []
    if isinstance(date_parts, list) and date_parts and isinstance(date_parts[0], list):
        try:
            year = int(date_parts[0][0])
        except (TypeError, ValueError, IndexError):
            year = None
    container = work.get("container-title") or []
    venue = (
        container[0]
        if isinstance(container, list) and container
        else work.get("publisher")
    )
    pdf_url: str | None = None
    landing_url: str | None = None
    for link in work.get("link") or []:
        if not isinstance(link, dict) or not link.get("URL"):
            continue
        content_type = link.get("content-type") or ""
        if content_type == "application/pdf" and not pdf_url:
            pdf_url = link["URL"]
        elif not landing_url:
            landing_url = link["URL"]
    licenses = work.get("license") or []
    license_urls = [
        item.get("URL")
        for item in licenses
        if isinstance(item, dict) and item.get("URL")
    ]
    return {
        "provider": "crossref_doi",
        "title": title,
        "authors": authors,
        "year": year,
        "venue": venue,
        "doi": _normalize_doi(work.get("DOI") or work.get("URL")),
        "is_oa": bool(pdf_url),
        "pdf_url": pdf_url,
        "landing_url": landing_url,
        "oa_license": license_urls[0] if license_urls else None,
    }


def search_openalex(
    query: str,
    *,
    title_search: bool,
    per_page: int,
    email: str | None,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
    delay: float = 0.0,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    params: dict[str, str] = {"per-page": str(per_page)}
    if title_search:
        params["filter"] = f"title.search:{query[:200]}"
    else:
        params["search"] = query[:300]
    if email:
        params["mailto"] = email
    url = OPENALEX_WORKS_URL + "?" + urllib.parse.urlencode(params)
    payload, error = _fetch_json(url, timeout, user_agent, urlopen, delay)
    if payload is None:
        return None, error
    works = payload.get("results") if isinstance(payload, dict) else payload
    if not isinstance(works, list):
        return None, "unexpected OpenAlex payload"
    return [_work_record(work) for work in works if isinstance(work, dict)], None


def resolve_doi(
    doi: str,
    email: str | None,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
    delay: float = 0.0,
    openalex_ok: bool = True,
) -> tuple[dict[str, Any] | None, str | None]:
    doi = _normalize_doi(doi) or ""
    encoded = urllib.parse.quote(doi, safe="/")
    unpaywall_error: str | None = None
    if email and openalex_ok:
        url = UNPAYWALL_URL + encoded + "?email=" + urllib.parse.quote(email)
        payload, unpaywall_error = _fetch_json(
            url, timeout, user_agent, urlopen, delay
        )
        if isinstance(payload, dict) and payload.get("is_oa"):
            location = payload.get("best_oa_location") or {}
            pdf_url = location.get("url_for_pdf") or location.get("url")
            if pdf_url:
                authors: list[str] = []
                for author in payload.get("z_authors") or []:
                    given = (author.get("given") or "").strip()
                    family = (author.get("family") or "").strip()
                    if given or family:
                        authors.append(f"{given} {family}".strip())
                return {
                    "provider": "unpaywall",
                    "title": payload.get("title") or "",
                    "authors": authors,
                    "year": payload.get("year"),
                    "venue": payload.get("journal_name") or payload.get("publisher"),
                    "doi": payload.get("doi") or doi,
                    "is_oa": True,
                    "pdf_url": pdf_url,
                    "landing_url": location.get("url") or payload.get("url"),
                    "match_score": 1.0,
                }, None
    openalex_details = "OpenAlex skipped after repeated rate limiting"
    if openalex_ok:
        url = OPENALEX_WORKS_URL + "/doi:" + encoded
        payload, openalex_error = _fetch_json(
            url, timeout, user_agent, urlopen, delay
        )
        if isinstance(payload, dict) and "id" in payload:
            record = _work_record(payload)
            record["provider"] = "openalex_doi"
            record["match_score"] = 1.0
            return record, None
        openalex_details = openalex_error or "OpenAlex DOI lookup returned no work"
    crossref_url = CROSSREF_WORKS_URL + "/" + encoded
    payload, crossref_error = _fetch_json(
        crossref_url, timeout, user_agent, urlopen, delay
    )
    if isinstance(payload, dict):
        message = payload.get("message")
        if isinstance(message, dict):
            record = _crossref_work_record(message)
            record["provider"] = "crossref_doi"
            record["match_score"] = 1.0
            return record, None
    details = []
    if unpaywall_error:
        details.append(f"Unpaywall: {unpaywall_error}")
    details.append(f"OpenAlex: {openalex_details}")
    details.append(f"Crossref: {crossref_error or 'Crossref DOI lookup returned no work'}")
    return None, "; ".join(details)


def resolve_title(
    citation: str,
    title_candidate: str | None,
    year: int | None,
    email: str | None,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
    delay: float = 0.0,
    openalex_ok: bool = True,
) -> tuple[dict[str, Any] | None, str | None]:
    best: dict[str, Any] | None = None
    best_score = 0.0
    errors: list[str] = []
    queries: list[tuple[str, bool]] = []
    if title_candidate:
        queries.append((title_candidate, True))
    elif citation and len(citation) <= 300:
        queries.append((citation, False))
    if openalex_ok:
        for query, title_search in queries:
            works, error = search_openalex(
                query,
                title_search=title_search,
                per_page=5,
                email=email,
                timeout=timeout,
                user_agent=user_agent,
                urlopen=urlopen,
                delay=delay,
            )
            if works is None:
                errors.append(error or "search failed")
                continue
            for work in works:
                if not work.get("title"):
                    continue
                if title_candidate:
                    score = _token_coverage(title_candidate, work["title"])
                else:
                    score = _token_coverage(work["title"], citation)
                if score > best_score:
                    best = dict(work)
                    best_score = score
    openalex_best_score = best_score
    crossref_query = (title_candidate or citation or "").strip()
    if crossref_query and (not best or best_score < 0.55):
        params: dict[str, str] = {
            "query.bibliographic": crossref_query[:300],
            "rows": "5",
        }
        url = CROSSREF_WORKS_URL + "?" + urllib.parse.urlencode(params)
        payload, crossref_error = _fetch_json(
            url, timeout, user_agent, urlopen, delay
        )
        if not isinstance(payload, dict):
            errors.append(f"Crossref: {crossref_error or 'search failed'}")
        else:
            message = payload.get("message") or {}
            works = message.get("items") if isinstance(message, dict) else None
            if not isinstance(works, list):
                errors.append("Crossref: unexpected search payload")
            else:
                for work in works:
                    if not isinstance(work, dict):
                        continue
                    record = _crossref_work_record(work)
                    if not record.get("title"):
                        continue
                    if title_candidate:
                        score = _token_coverage(title_candidate, record["title"])
                    else:
                        score = _token_coverage(record["title"], citation)
                    if score > best_score:
                        best = dict(record)
                        best_score = score
    if best and best_score >= 0.55:
        best["provider"] = "crossref_title" if "crossref" in (best.get("provider") or "") else "openalex_title"
        best["match_score"] = round(best_score, 3)
        return best, None
    if best:
        return None, f"title match too weak ({best_score:.2f})"
    if openalex_best_score > 0 and not errors:
        return None, f"title match too weak ({openalex_best_score:.2f})"
    return None, "; ".join(errors) if errors else "no title search results"


def fetch_recent_works(
    concept: str,
    per_page: int,
    email: str | None,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
    delay: float = 0.0,
    openalex_ok: bool = True,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    openalex_error: str | None = None
    if openalex_ok:
        params: dict[str, str] = {
            "search": concept[:300],
            "sort": "publication_date:desc",
            "per-page": str(per_page),
        }
        if email:
            params["mailto"] = email
        url = OPENALEX_WORKS_URL + "?" + urllib.parse.urlencode(params)
        payload, error = _fetch_json(url, timeout, user_agent, urlopen, delay)
        if payload is None:
            openalex_error = error
        else:
            works = payload.get("results") if isinstance(payload, dict) else payload
            if isinstance(works, list):
                return [_work_record(work) for work in works if isinstance(work, dict)], None
            openalex_error = "unexpected OpenAlex payload"
    else:
        openalex_error = "OpenAlex skipped after repeated rate limiting"
    params = {
        "query": concept[:300],
        "rows": str(per_page),
        "filter": "from-pub-date:2015-01-01",
        "sort": "published",
        "order": "desc",
    }
    url = CROSSREF_WORKS_URL + "?" + urllib.parse.urlencode(params)
    payload, crossref_error = _fetch_json(url, timeout, user_agent, urlopen, delay)
    if not isinstance(payload, dict):
        return None, f"OpenAlex: {openalex_error}; Crossref: {crossref_error or 'search failed'}"
    message = payload.get("message") or {}
    works = message.get("items") if isinstance(message, dict) else None
    if not isinstance(works, list):
        return None, f"OpenAlex: {openalex_error}; Crossref: unexpected search payload"
    records = []
    for work in works:
        if not isinstance(work, dict):
            continue
        record = _crossref_work_record(work)
        if record.get("title") and _is_substantive_work(record):
            records.append(record)
    return records, None


def _unverified_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _download_pdf_once(
    url: str,
    dest: Path,
    max_bytes: int,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
    context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    request = _request(url, user_agent, "application/pdf,*/*", context)
    with urlopen(request, timeout=timeout) as response:
        content_type = response.headers.get("Content-Type", "")
        total = 0
        hasher = hashlib.sha256()
        with dest.open("wb") as handle:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"PDF exceeds {max_bytes} bytes")
                hasher.update(chunk)
                handle.write(chunk)
    if not dest.read_bytes()[:5].startswith(PDF_MAGIC):
        dest.unlink(missing_ok=True)
        return {"ok": False, "reason": "response is not a PDF"}
    return {
        "ok": True,
        "content_hash": hasher.hexdigest(),
        "bytes": total,
        "content_type": content_type,
    }


def download_pdf(
    url: str,
    dest: Path,
    max_bytes: int,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
) -> dict[str, Any]:
    try:
        return _download_pdf_once(
            url, dest, max_bytes, timeout, user_agent, urlopen
        )
    except urllib.error.URLError as exc:
        if not isinstance(exc.reason, ssl.SSLCertVerificationError):
            dest.unlink(missing_ok=True)
            return {
                "ok": False,
                "reason": f"{type(exc).__name__}: {exc}",
            }
    except Exception as exc:
        dest.unlink(missing_ok=True)
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    dest.unlink(missing_ok=True)
    try:
        result = _download_pdf_once(
            url,
            dest,
            max_bytes,
            timeout,
            user_agent,
            urlopen,
            _unverified_ssl_context(),
        )
        result["relaxed_ssl"] = True
        return result
    except Exception as exc:
        dest.unlink(missing_ok=True)
        return {
            "ok": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def _seen_key(title: str | None, doi: str | None) -> str:
    if doi:
        return "doi:" + doi.lower().strip()
    normalized = _normalize_text(title)
    return "title:" + normalized if normalized else ""


def _manual_record(
    item: dict[str, Any],
    resolved: dict[str, Any] | None,
    reason: str,
) -> dict[str, Any]:
    title = (
        (resolved or {}).get("title")
        or item.get("title_candidate")
        or item.get("citation")
        or "unknown"
    )
    authors = (resolved or {}).get("authors") or []
    year = (resolved or {}).get("year") or item.get("year")
    doi = (resolved or {}).get("doi") or item.get("doi")
    urls: list[dict[str, str]] = []
    if resolved:
        if resolved.get("pdf_url"):
            urls.append({"kind": "pdf", "url": resolved["pdf_url"]})
        if resolved.get("landing_url"):
            urls.append({"kind": "landing", "url": resolved["landing_url"]})
    urls.extend({"kind": "source", "url": url} for url in (item.get("urls") or []))
    if item.get("entry_slug"):
        urls.append({"kind": "sep_entry", "url": f"{SEP_BASE}{item['entry_slug']}/"})
    key = f"doi:{doi.lower()}" if doi else "title:" + _normalize_text(title)
    return {
        "key": key,
        "item_id": item["item_id"],
        "title": title,
        "authors": authors,
        "year": year,
        "doi": doi,
        "reason": reason,
        "suggested_urls": urls,
        "source": {
            "kind": item.get("source_kind"),
            "entry_slug": item.get("entry_slug"),
            "entry_title": item.get("entry_title"),
        },
    }


def _process_candidate(
    item: dict[str, Any],
    resolved: dict[str, Any] | None,
    error: str | None,
    files_dir: Path,
    downloads: dict[str, int],
    max_bytes: int,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    record = {
        "item_id": item["item_id"],
        "source_kind": item.get("source_kind"),
        "entry_slug": item.get("entry_slug"),
        "entry_title": item.get("entry_title"),
        "citation": item.get("citation"),
        "title_candidate": item.get("title_candidate"),
        "year": item.get("year"),
        "doi": item.get("doi"),
        "urls": item.get("urls") or [],
        "resolved": resolved,
        "resolve_error": error,
        "download": "none",
    }
    queue_item: dict[str, Any] | None = None
    if resolved and resolved.get("pdf_url"):
        if downloads["left"] > 0:
            local = files_dir / f"{item['item_id']}.pdf"
            result = download_pdf(
                resolved["pdf_url"],
                local,
                max_bytes,
                timeout,
                user_agent,
                urlopen,
            )
            if result["ok"]:
                resolved["local_file"] = local.name
                resolved["content_hash"] = result["content_hash"]
                resolved["bytes"] = result["bytes"]
                if result.get("relaxed_ssl"):
                    resolved["download_note"] = "relaxed SSL retry succeeded"
                record["download"] = "ok"
                downloads["left"] -= 1
            else:
                record["download"] = "failed"
                queue_item = _manual_record(
                    item, resolved, "download_failed: " + result["reason"]
                )
        else:
            record["download"] = "skipped_limit"
    else:
        queue_item = _manual_record(item, resolved, error or "no open access location")
    return record, queue_item


def _append_manual(
    queue: list[dict[str, Any]],
    record: dict[str, Any] | None,
    seen: set[str],
) -> None:
    if record is None:
        return
    key = record["key"]
    if key in seen:
        return
    seen.add(key)
    queue.append(record)


def _resolve_citation(
    item: dict[str, Any],
    email: str | None,
    timeout: int,
    user_agent: str,
    urlopen: Callable[..., Any],
    delay: float,
    openalex_ok: bool = True,
) -> tuple[dict[str, Any] | None, str | None]:
    doi = item.get("doi")
    if doi:
        resolved, error = resolve_doi(
            doi, email, timeout, user_agent, urlopen, delay, openalex_ok
        )
        if resolved:
            return resolved, None
        resolved, title_error = resolve_title(
            item.get("citation") or "",
            item.get("title_candidate"),
            item.get("year"),
            email,
            timeout,
            user_agent,
            urlopen,
            delay,
            openalex_ok,
        )
        if resolved:
            return resolved, None
        return None, f"DOI lookup failed ({error}); title search failed ({title_error})"
    return resolve_title(
        item.get("citation") or "",
        item.get("title_candidate"),
        item.get("year"),
        email,
        timeout,
        user_agent,
        urlopen,
        delay,
        openalex_ok,
    )


def _markdown_cell(value: Any) -> str:
    text = str(value if value is not None else "")
    return re.sub(r"\s+", " ", text).replace("|", "\\|").strip()


def _build_report(
    run_id: str,
    params: dict[str, Any],
    inputs: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    manual_queue: list[dict[str, Any]],
    notes: list[str],
    finished: str,
) -> str:
    lines = [f"# Literature acquisition report {run_id}", ""]
    lines.append(f"- Generated: {finished}")
    if params.get("concept"):
        lines.append(f"- Concept: {params['concept']}")
    if inputs:
        lines.append("- SEP entries: " + ", ".join(item["slug"] for item in inputs))
    lines.append("")
    downloaded = [candidate for candidate in candidates if candidate["download"] == "ok"]
    lines.append(f"## Downloaded ({len(downloaded)})")
    lines.append("")
    lines.append("| File | Title | Authors | Year | DOI |")
    lines.append("|---|---|---|---|---|")
    for candidate in downloaded:
        resolved = candidate["resolved"] or {}
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                _markdown_cell(resolved.get("local_file")),
                _markdown_cell(resolved.get("title")),
                _markdown_cell(", ".join(resolved.get("authors") or [])),
                _markdown_cell(resolved.get("year")),
                _markdown_cell(resolved.get("doi")),
            )
        )
    lines.append("")
    lines.append(f"## Manual download queue ({len(manual_queue)})")
    lines.append("")
    lines.append("| Title | Authors | Year | DOI | Suggested URLs | Reason |")
    lines.append("|---|---|---|---|---|---|")
    for entry in manual_queue:
        urls = ", ".join(
            f"{url.get('kind')}: {url.get('url')}"
            for url in entry.get("suggested_urls") or []
        )
        lines.append(
            "| {} | {} | {} | {} | {} | {} |".format(
                _markdown_cell(entry.get("title")),
                _markdown_cell(", ".join(entry.get("authors") or [])),
                _markdown_cell(entry.get("year")),
                _markdown_cell(entry.get("doi")),
                _markdown_cell(urls),
                _markdown_cell(entry.get("reason")),
            )
        )
    lines.append("")
    lines.append("## Notes")
    lines.extend(f"- {_markdown_cell(note)}" for note in notes)
    return "\n".join(lines) + "\n"


def run_acquisition(
    *,
    output: str | Path,
    concept: str | None = None,
    sep_entries: list[str] | tuple[str, ...] = (),
    dois: list[str] | tuple[str, ...] = (),
    email: str | None = None,
    recent_max: int = 10,
    max_downloads: int = 25,
    max_items: int | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: int = 30,
    api_delay: float = 0.0,
    user_agent: str | None = None,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    if (
        recent_max < 0
        or max_downloads < 0
        or max_bytes <= 0
        or timeout <= 0
        or (max_items is not None and max_items <= 0)
    ):
        raise ValueError("numeric limits must be positive")
    started = datetime.now(timezone.utc)
    run_id = (
        "acquisition-"
        + started.strftime("%Y%m%d-%H%M%S")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    run_dir = Path(output).expanduser().resolve() / run_id
    files_dir = run_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=False)
    user_agent = user_agent or f"{WORKER_NAME}/{WORKER_VERSION}"
    params: dict[str, Any] = {
        "concept": concept,
        "sep_entries": list(sep_entries),
        "dois": list(dois),
        "email": email,
        "recent_max": recent_max,
        "max_downloads": max_downloads,
        "max_items": max_items,
        "max_bytes": max_bytes,
        "timeout": timeout,
        "api_delay": api_delay,
    }
    notes: list[str] = []
    if not email:
        notes.append(
            "no --email provided: Unpaywall skipped and OpenAlex polite pool disabled"
        )
    inputs: list[dict[str, Any]] = []
    sep_records: list[dict[str, Any]] = []
    bibliography: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    manual_queue: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_manual: set[str] = set()

    for supplied in sep_entries:
        try:
            slug, url = _sep_slug_url(str(supplied))
        except ValueError as exc:
            notes.append(str(exc))
            continue
        entry, error = fetch_sep_entry(url, timeout, user_agent, urlopen)
        if entry is None:
            notes.append(f"SEP entry {slug}: {error}")
            continue
        inputs.append(
            {
                "kind": "sep_entry",
                "slug": slug,
                "url": url,
                "content_hash": entry["content_hash"],
                "bytes": entry["bytes"],
            }
        )
        sep_records.append(
            {
                "slug": slug,
                "title": entry["title"],
                "pubinfo": entry["pubinfo"],
                "url": entry["url"],
                "bibliography": entry["bibliography"],
                "related_entries": entry["related_entries"],
            }
        )
        for item in entry["bibliography"]:
            item_id = f"item_{len(bibliography) + 1:04d}"
            record = {
                "item_id": item_id,
                "source_kind": "sep_bibliography",
                "entry_slug": slug,
                "entry_title": entry["title"],
                **item,
            }
            key = _seen_key(record.get("title_candidate"), record.get("doi"))
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            bibliography.append(record)
        notes.append(
            f"SEP {slug}: {len(entry['bibliography'])} bibliography items, "
            f"{len(entry['related_entries'])} related entries"
        )

    if max_items is not None and len(bibliography) > max_items:
        notes.append(
            f"bibliography truncated: {len(bibliography)} items limited to {max_items}"
        )
        bibliography = bibliography[:max_items]

    downloads = {"left": max_downloads}
    rate_limit_streak = 0
    rate_limit_note_added = False
    openalex_degraded = False
    for item in bibliography:
        if rate_limit_streak >= MAX_CONSECUTIVE_RATE_LIMITS:
            if not rate_limit_note_added:
                notes.append(
                    "OpenAlex repeatedly returned 429; remaining bibliography "
                    "items were queued for manual download"
                )
                rate_limit_note_added = True
            resolved, error = None, "skipped after repeated rate limiting (429)"
        else:
            resolved, error = _resolve_citation(
                item,
                email,
                timeout,
                user_agent,
                urlopen,
                api_delay,
                not openalex_degraded,
            )
            if "429" in (error or ""):
                rate_limit_streak += 1
                openalex_degraded = True
                if (
                    rate_limit_streak >= MAX_CONSECUTIVE_RATE_LIMITS
                    and not rate_limit_note_added
                ):
                    notes.append(
                        "OpenAlex repeatedly returned 429; remaining bibliography "
                        "items were queued for manual download"
                    )
                    rate_limit_note_added = True
            else:
                rate_limit_streak = 0
        record, queue_item = _process_candidate(
            item,
            resolved,
            error,
            files_dir,
            downloads,
            max_bytes,
            timeout,
            user_agent,
            urlopen,
        )
        candidates.append(record)
        _append_manual(manual_queue, queue_item, seen_manual)

    next_item_id = len(bibliography) + 1
    explicit_items: list[dict[str, Any]] = []
    for supplied_doi in dois:
        doi = _normalize_doi(supplied_doi)
        if not doi:
            notes.append(f"invalid DOI skipped: {supplied_doi}")
            continue
        item_id = f"item_{next_item_id:04d}"
        next_item_id += 1
        explicit_items.append(
            {
                "item_id": item_id,
                "source_kind": "explicit_doi",
                "entry_slug": None,
                "entry_title": None,
                "citation": "",
                "title_candidate": None,
                "year": None,
                "doi": doi,
                "urls": [],
            }
        )
    if explicit_items:
        notes.append(f"{len(explicit_items)} explicit DOI item(s) queued for resolution")
    for item in explicit_items:
        resolved, error = _resolve_citation(
            item,
            email,
            timeout,
            user_agent,
            urlopen,
            api_delay,
            not openalex_degraded,
        )
        if "429" in (error or ""):
            openalex_degraded = True
        record, queue_item = _process_candidate(
            item,
            resolved,
            error,
            files_dir,
            downloads,
            max_bytes,
            timeout,
            user_agent,
            urlopen,
        )
        candidates.append(record)
        _append_manual(manual_queue, queue_item, seen_manual)

    if concept:
        recents, error = fetch_recent_works(
            concept,
            recent_max,
            email,
            timeout,
            user_agent,
            urlopen,
            api_delay,
            not openalex_degraded,
        )
        if recents is None:
            notes.append("recent-works search failed: " + (error or "unknown"))
        else:
            providers = sorted({work.get("provider") or "unknown" for work in recents})
            notes.append(
                f"recent search returned {len(recents)} works via "
                + ", ".join(providers)
            )
            for work in recents:
                key = _seen_key(work.get("title"), work.get("doi"))
                if key and key in seen:
                    continue
                if key:
                    seen.add(key)
                item_id = f"item_{next_item_id:04d}"
                next_item_id += 1
                item = {
                    "item_id": item_id,
                    "source_kind": "provider_recent",
                    "entry_slug": None,
                    "entry_title": concept,
                    "citation": work.get("title") or "",
                    "title_candidate": work.get("title"),
                    "year": work.get("year"),
                    "doi": work.get("doi"),
                    "urls": [work["landing_url"]] if work.get("landing_url") else [],
                }
                resolved, error = work, None
                if not work.get("pdf_url"):
                    error = "no open access PDF in provider record"
                    if work.get("doi"):
                        resolved, error = resolve_doi(
                            work["doi"],
                            email,
                            timeout,
                            user_agent,
                            urlopen,
                            api_delay,
                        )
                record, queue_item = _process_candidate(
                    item,
                    resolved,
                    error,
                    files_dir,
                    downloads,
                    max_bytes,
                    timeout,
                    user_agent,
                    urlopen,
                )
                candidates.append(record)
                _append_manual(manual_queue, queue_item, seen_manual)

    _write_jsonl(run_dir / "sep-entries.jsonl", sep_records)
    _write_jsonl(run_dir / "bibliography.jsonl", bibliography)
    _write_jsonl(run_dir / "candidates.jsonl", candidates)
    _write_jsonl(run_dir / "manual-queue.jsonl", manual_queue)
    finished = datetime.now(timezone.utc)
    (run_dir / "report.md").write_text(
        _build_report(
            run_id,
            params,
            inputs,
            candidates,
            manual_queue,
            notes,
            finished.isoformat(),
        ),
        encoding="utf-8",
    )
    outputs: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            outputs.append(
                {
                    "path": str(path.relative_to(run_dir)).replace("\\", "/"),
                    "content_hash": _sha256_file(path),
                    "bytes": path.stat().st_size,
                }
            )
    summary = {
        "sep_entries": len(sep_records),
        "bibliography_items": len(bibliography),
        "recent_works": sum(
            1 for candidate in candidates if candidate["source_kind"] == "provider_recent"
        ),
        "downloaded": sum(
            1 for candidate in candidates if candidate["download"] == "ok"
        ),
        "manual_queue": len(manual_queue),
        "skipped_download_limit": sum(
            1 for candidate in candidates if candidate["download"] == "skipped_limit"
        ),
    }
    manifest = {
        "schema_version": STAGING_SCHEMA_VERSION,
        "worker": {"name": WORKER_NAME, "version": WORKER_VERSION},
        "run_id": run_id,
        "params": params,
        "inputs": inputs,
        "outputs": outputs,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "exit_code": 0,
        "summary": summary,
        "notes": notes,
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        "ok": True,
        "run_id": run_id,
        "run_dir": str(run_dir),
        "manifest": str(run_dir / "manifest.json"),
        "summary": summary,
        "notes": notes,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="research-kb-acquisition",
        description=(
            "External literature acquisition worker. Fetches SEP bibliography, "
            "resolves open-access versions through OpenAlex/Unpaywall, downloads "
            "PDFs into a staging run directory, and writes a manifest plus a "
            "manual download queue. It never writes the authoritative database."
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Staging parent directory; a timestamped run directory is created inside it",
    )
    parser.add_argument(
        "--concept",
        default=None,
        help="Research concept used for an OpenAlex recent-works search",
    )
    parser.add_argument(
        "--sep-entry",
        action="append",
        default=[],
        metavar="SLUG_OR_URL",
        help="SEP entry slug or URL; repeatable",
    )
    parser.add_argument(
        "--doi",
        action="append",
        default=[],
        metavar="DOI",
        help="DOI to resolve and download if open access; repeatable",
    )
    parser.add_argument(
        "--email",
        default=None,
        help="Contact email enabling Unpaywall and the OpenAlex polite pool",
    )
    parser.add_argument("--recent-max", type=int, default=10)
    parser.add_argument("--max-downloads", type=int, default=25)
    parser.add_argument(
        "--max-items",
        type=int,
        default=None,
        help="Maximum SEP bibliography items to resolve in one run; default unlimited",
    )
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--api-delay",
        type=float,
        default=0.25,
        help="Seconds to sleep before each OpenAlex/Unpaywall request",
    )
    parser.add_argument("--user-agent", default=None)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        result = run_acquisition(
            output=args.output,
            concept=args.concept,
            sep_entries=args.sep_entry,
            dois=args.doi,
            email=args.email,
            recent_max=args.recent_max,
            max_downloads=args.max_downloads,
            max_items=args.max_items,
            max_bytes=args.max_bytes,
            timeout=args.timeout,
            api_delay=args.api_delay,
            user_agent=args.user_agent,
        )
    except (OSError, ValueError) as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False),
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
