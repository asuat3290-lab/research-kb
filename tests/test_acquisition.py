from __future__ import annotations

import hashlib
import json
import os
import ssl
import tempfile
import unittest
import unittest.mock
import urllib.error
import urllib.parse
from pathlib import Path

from research_kb.acquisition import (
    WORKER_NAME,
    download_pdf,
    fetch_recent_works,
    resolve_doi,
    resolve_title,
    run_acquisition,
    _SepEntryParser,
    _extract_doi,
    _extract_title,
    _extract_year,
    _is_substantive_work,
    _normalize_doi,
    _sep_slug_from_url,
)


_SEP_HTML = """<!DOCTYPE html>
<html><head><title>Lukacs</title></head>
<body>
<div id="article">
<h1>Georg Lukacs</h1>
<div id="pubinfo"><em>First published Mon Nov 4, 2013; substantive revision Thu Jan 1, 2026</em></div>
<div id="article-content">
<div id="bibliography">
<h2 id="Bib">Bibliography</h2>
<h3 id="Sec">Secondary Sources</h3>
<ul class="hanging">
<li>Anderson, Perry, 1976, <em>Considerations on Western Marxism</em>, London: NLB.</li>
<li>Feenberg, Andrew, 2014, &ldquo;The Philosophy of Praxis: Marx, Lukacs and the Frankfurt School,&rdquo; in <em>The Philosophy of Praxis</em>, London: Verso, pp. 1&ndash;30.</li>
<li>Honneth, Axel, 2008, <em>Reification: A New Look at an Old Idea</em>, Oxford: Oxford University Press, doi:10.1093/acprof:oso/9780195320466.001.0001.</li>
</ul>
</div>
<div id="related-entries">
<p>
 <a href="../hegel/">Hegel, Georg Wilhelm Friedrich</a> |
 <a href="../marx/">Marx, Karl</a>
</p>
</div>
</div>
</div>
</body></html>"""

_PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


def _json_response(payload: object) -> "_FakeResponse":
    return _FakeResponse(json.dumps(payload))


class _FakeResponse:
    def __init__(self, body: bytes | str, content_type: str = "application/json") -> None:
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.headers = {"Content-Type": content_type}

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            data, self.body = self.body, b""
            return data
        data, self.body = self.body[:size], self.body[size:]
        return data

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class _FakeUrlOpener:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[str] = []

    def __call__(self, request, timeout: int = 30) -> "_FakeResponse":
        url = request.full_url if hasattr(request, "full_url") else str(request)
        self.calls.append(url)
        try:
            response = self.handler(url, request)
        except TypeError:
            response = self.handler(url)
        if isinstance(response, Exception):
            raise response
        return response


def _openalex_work(**overrides) -> dict:
    work = {
        "id": "https://openalex.org/W123",
        "title": "The Philosophy of Praxis: Marx, Lukacs and the Frankfurt School",
        "publication_year": 2014,
        "authorships": [{"author": {"display_name": "Andrew Feenberg"}}],
        "doi": "https://doi.org/10.1000/praxis",
        "primary_location": {
            "source": {"display_name": "Verso"},
            "landing_page_url": "https://example.org/book",
            "pdf_url": None,
        },
        "best_oa_location": {
            "pdf_url": "https://example.org/praxis.pdf",
            "landing_page_url": "https://example.org/book",
            "is_oa": True,
        },
        "open_access": {"is_oa": True},
    }
    work.update(overrides)
    return work


def _unpaywall_payload() -> dict:
    return {
        "is_oa": True,
        "title": "Reification: A New Look at an Old Idea",
        "year": 2008,
        "journal_name": "Oxford University Press",
        "doi": "10.1093/acprof:oso/9780195320466.001.0001",
        "z_authors": [{"given": "Axel", "family": "Honneth"}],
        "best_oa_location": {
            "url_for_pdf": "https://example.org/reification.pdf",
            "url": "https://example.org/reification",
        },
        "url": "https://example.org/reification",
    }


def _crossref_payload(**overrides) -> dict:
    message = {
        "DOI": "10.1000/crossref-work",
        "title": ["Lukacs and the Question of Totality"],
        "author": [{"given": "Gyorgy", "family": "Markus"}],
        "issued": {"date-parts": [[2023]]},
        "container-title": ["Historical Materialism"],
        "link": [
            {
                "URL": "https://example.org/lukacs-totality.pdf",
                "content-type": "application/pdf",
            },
            {
                "URL": "https://example.org/lukacs-totality-landing",
                "content-type": "text/html",
            },
        ],
        "license": [{"URL": "https://creativecommons.org/licenses/by/4.0/"}],
    }
    message.update(overrides)
    return {"status": "ok", "message-type": "work", "message": message}


def _e2e_handler():
    def handler(url: str):
        if url.startswith("https://plato.stanford.edu/entries/lukacs/"):
            return _FakeResponse(_SEP_HTML, "text/html")
        if url.startswith("https://api.unpaywall.org/v2/"):
            return _json_response(_unpaywall_payload())
        if (
            url.startswith("https://api.openalex.org/works?")
            and "publication_date" in url
        ):
            recent = _openalex_work(
                id="https://openalex.org/W999",
                title="Recent Lukacs Studies",
                publication_year=2025,
                doi="https://doi.org/10.1000/recent",
                best_oa_location={
                    "pdf_url": "https://example.org/recent.pdf",
                    "landing_page_url": "https://example.org/recent",
                    "is_oa": True,
                },
            )
            return _json_response({"results": [recent]})
        if url.startswith("https://api.openalex.org/works?") and "title.search" in url:
            if "Praxis" in urllib.parse.unquote(url):
                return _json_response({"results": [_openalex_work()]})
            return _json_response({"results": []})
        if url.startswith("https://api.openalex.org/works?"):
            return _json_response({"results": []})
        if url.startswith("https://api.openalex.org/works/doi:"):
            return _json_response(_openalex_work())
        if url.startswith("https://api.crossref.org/works"):
            return _json_response({"message": {"items": []}})
        if url.startswith("https://example.org/"):
            return _FakeResponse(_PDF, "application/pdf")
        raise AssertionError("unexpected URL: " + url)

    return handler


class SepParserTests(unittest.TestCase):
    def test_sep_parser_extracts_bibliography_and_related(self) -> None:
        parser = _SepEntryParser()
        parser.feed(_SEP_HTML)
        parser.close()
        self.assertEqual(parser.title, "Georg Lukacs")
        self.assertEqual(len(parser.bibliography), 3)
        self.assertEqual(parser.bibliography[0]["section"], "Secondary Sources")
        related = [
            (_sep_slug_from_url(item["url"]), item["label"])
            for item in parser.related
        ]
        self.assertIn(("hegel", "Hegel, Georg Wilhelm Friedrich"), related)

    def test_citation_metadata_extraction(self) -> None:
        citation = (
            "Honneth, Axel, 2008, Reification: A New Look at an Old Idea, "
            "Oxford: Oxford University Press, "
            "doi:10.1093/acprof:oso/9780195320466.001.0001."
        )
        self.assertEqual(
            _extract_doi(citation),
            "10.1093/acprof:oso/9780195320466.001.0001",
        )
        self.assertEqual(_extract_year(citation), 2008)
        self.assertEqual(
            _extract_title('2014, "The Philosophy of Praxis," in Essays', None),
            "The Philosophy of Praxis",
        )


class ResolverTests(unittest.TestCase):
    def test_normalize_doi(self) -> None:
        self.assertEqual(
            _normalize_doi("doi:10.1093/acprof:oso/9780195320466.001.0001."),
            "10.1093/acprof:oso/9780195320466.001.0001",
        )
        self.assertEqual(
            _normalize_doi("https://doi.org/10.1000/recent"),
            "10.1000/recent",
        )
        self.assertIsNone(_normalize_doi(""))

    def test_resolve_doi_uses_unpaywall_then_openalex(self) -> None:
        opener = _FakeUrlOpener(_e2e_handler())
        record, error = resolve_doi(
            "10.1093/acprof:oso/9780195320466.001.0001",
            "me@example.com",
            30,
            "test-agent",
            opener,
        )
        self.assertIsNone(error)
        self.assertEqual(record["provider"], "unpaywall")
        self.assertEqual(record["pdf_url"], "https://example.org/reification.pdf")

    def test_resolve_doi_falls_back_to_openalex(self) -> None:
        def handler(url: str):
            if url.startswith("https://api.unpaywall.org/"):
                return urllib.error.URLError("blocked")
            if url.startswith("https://api.openalex.org/works/doi:"):
                return _json_response(_openalex_work())
            raise AssertionError("unexpected URL: " + url)

        opener = _FakeUrlOpener(handler)
        record, error = resolve_doi(
            "10.1000/praxis", "me@example.com", 30, "test-agent", opener
        )
        self.assertIsNone(error)
        self.assertEqual(record["provider"], "openalex_doi")
        self.assertEqual(record["pdf_url"], "https://example.org/praxis.pdf")

    def test_resolve_doi_falls_back_to_crossref(self) -> None:
        def handler(url: str):
            if url.startswith("https://api.unpaywall.org/"):
                return urllib.error.URLError("blocked")
            if url.startswith("https://api.openalex.org/works/doi:"):
                return urllib.error.HTTPError(
                    url, 404, "Not Found", {}, None
                )
            if url.startswith("https://api.crossref.org/works/10.1000/"):
                return _json_response(
                    _crossref_payload(
                        DOI="10.1000/praxis",
                        title=["The Philosophy of Praxis: Marx, Lukacs and the Frankfurt School"],
                    )
                )
            raise AssertionError("unexpected URL: " + url)

        opener = _FakeUrlOpener(handler)
        record, error = resolve_doi(
            "10.1000/praxis", "me@example.com", 30, "test-agent", opener
        )
        self.assertIsNone(error)
        self.assertEqual(record["provider"], "crossref_doi")
        self.assertEqual(record["pdf_url"], "https://example.org/lukacs-totality.pdf")
        self.assertEqual(record["oa_license"], "https://creativecommons.org/licenses/by/4.0/")

    def test_resolve_title_matches_and_rejects_weak_titles(self) -> None:
        opener = _FakeUrlOpener(_e2e_handler())
        record, error = resolve_title(
            "Feenberg, Andrew, 2014, The Philosophy of Praxis",
            "The Philosophy of Praxis: Marx, Lukacs and the Frankfurt School",
            2014,
            None,
            30,
            "test-agent",
            opener,
        )
        self.assertIsNone(error)
        self.assertEqual(record["provider"], "openalex_title")

        def weak_handler(url: str):
            if "title.search" in url:
                return _json_response(
                    {"results": [_openalex_work(title="Unrelated Study of Nothing")]}
                )
            if url.startswith("https://api.crossref.org/works"):
                return _json_response({"message": {"items": []}})
            return _json_response({"results": []})

        weak_opener = _FakeUrlOpener(weak_handler)
        record, error = resolve_title(
            "Totally Different Book",
            "Totally Different Book",
            None,
            None,
            30,
            "test-agent",
            weak_opener,
        )
        self.assertIsNone(record)
        self.assertIsNotNone(error)

    def test_resolve_title_falls_back_to_crossref(self) -> None:
        def handler(url: str):
            if url.startswith("https://api.openalex.org/works?") and "title.search" in url:
                return _json_response({"results": []})
            if url.startswith("https://api.crossref.org/works?") and "query.bibliographic" in url:
                return _json_response(
                    {
                        "message": {
                            "items": [
                                _crossref_payload(
                                    DOI="10.1000/crossref-work",
                                    title=["Lukacs and the Question of Totality"],
                                )["message"]
                            ]
                        }
                    }
                )
            return _json_response({"results": []})

        opener = _FakeUrlOpener(handler)
        record, error = resolve_title(
            "Markus, 2023, Lukacs and the Question of Totality",
            "Lukacs and the Question of Totality",
            2023,
            None,
            30,
            "test-agent",
            opener,
        )
        self.assertIsNone(error)
        self.assertEqual(record["provider"], "crossref_title")
        self.assertEqual(record["doi"], "10.1000/crossref-work")
        self.assertEqual(record["year"], 2023)

    def test_fetch_recent_works_falls_back_to_crossref(self) -> None:
        def handler(url: str):
            if url.startswith("https://api.openalex.org/works?"):
                return urllib.error.HTTPError(
                    url, 429, "Too Many Requests", {}, None
                )
            if url.startswith("https://api.crossref.org/works?") and "from-pub-date" in url:
                return _json_response(
                    {
                        "message": {
                            "items": [
                                _crossref_payload(
                                    title=["Contents"],
                                    DOI="10.1515/9781478062455-toc",
                                )["message"],
                                _crossref_payload()["message"],
                            ]
                        }
                    }
                )
            raise AssertionError("unexpected URL: " + url)

        opener = _FakeUrlOpener(handler)
        with unittest.mock.patch("research_kb.acquisition.time.sleep"):
            works, error = fetch_recent_works(
                "Lukacs totality",
                3,
                None,
                30,
                "test-agent",
                opener,
                delay=0.0,
                openalex_ok=False,
            )
        self.assertIsNone(error)
        self.assertEqual(len(works), 1)
        self.assertEqual(works[0]["provider"], "crossref_doi")
        self.assertEqual(works[0]["pdf_url"], "https://example.org/lukacs-totality.pdf")

    def test_resolve_title_skips_openalex_when_degraded(self) -> None:
        def handler(url: str):
            if url.startswith("https://api.crossref.org/works?"):
                return _json_response(
                    {
                        "message": {
                            "items": [
                                _crossref_payload(
                                    title=["Lukacs and the Question of Totality"],
                                )["message"]
                            ]
                        }
                    }
                )
            raise AssertionError("OpenAlex should not be called: " + url)

        opener = _FakeUrlOpener(handler)
        record, error = resolve_title(
            "Markus, 2023, Lukacs and the Question of Totality",
            "Lukacs and the Question of Totality",
            2023,
            None,
            30,
            "test-agent",
            opener,
            delay=0.0,
            openalex_ok=False,
        )
        self.assertIsNone(error)
        self.assertEqual(record["provider"], "crossref_title")

    def test_substantive_work_filter_rejects_front_matter(self) -> None:
        self.assertTrue(
            _is_substantive_work(
                {"title": "Reification: A New Look at an Old Idea", "doi": "10.1000/real"}
            )
        )
        self.assertFalse(
            _is_substantive_work({"title": "Contents", "doi": "10.1515/x-toc"})
        )
        self.assertFalse(
            _is_substantive_work({"title": "Index", "doi": "10.1000/y"})
        )


class DownloadTests(unittest.TestCase):
    def test_download_pdf_validates_magic_and_hash(self) -> None:
        opener = _FakeUrlOpener(lambda url: _FakeResponse(_PDF, "application/pdf"))
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("RESEARCH_KB_TEST_TMP")
        ) as tmp:
            dest = Path(tmp) / "out.pdf"
            result = download_pdf(
                "https://example.org/paper.pdf", dest, 1024, 30, "test-agent", opener
            )
            self.assertEqual(dest.read_bytes(), _PDF)
        self.assertTrue(result["ok"])
        self.assertEqual(result["content_hash"], hashlib.sha256(_PDF).hexdigest())

    def test_download_rejects_non_pdf(self) -> None:
        opener = _FakeUrlOpener(
            lambda url: _FakeResponse("<html>no pdf</html>", "text/html")
        )
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("RESEARCH_KB_TEST_TMP")
        ) as tmp:
            dest = Path(tmp) / "out.pdf"
            result = download_pdf(
                "https://example.org/page", dest, 1024, 30, "test-agent", opener
            )
        self.assertFalse(result["ok"])
        self.assertFalse(dest.exists())

    def test_download_retries_once_with_relaxed_ssl(self) -> None:
        calls: list[dict[str, object]] = []

        def handler(url: str, request=None):
            context = getattr(request, "context", None)
            calls.append({"url": url, "context": context})
            if len(calls) == 1:
                raise urllib.error.URLError(
                    ssl.SSLCertVerificationError(1, "unable to get local issuer certificate")
                )
            return _FakeResponse(_PDF, "application/pdf")

        opener = _FakeUrlOpener(handler)
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("RESEARCH_KB_TEST_TMP")
        ) as tmp:
            dest = Path(tmp) / "out.pdf"
            result = download_pdf(
                "https://example.org/paper.pdf", dest, 1024, 30, "test-agent", opener
            )
            self.assertEqual(dest.read_bytes(), _PDF)
        self.assertTrue(result["ok"])
        self.assertTrue(result["relaxed_ssl"])
        self.assertEqual(len(calls), 2)
        self.assertIsNone(calls[0]["context"])
        self.assertIsNotNone(calls[1]["context"])

    def test_download_does_not_relax_for_non_ssl_errors(self) -> None:
        opener = _FakeUrlOpener(
            lambda url: urllib.error.URLError("connection refused")
        )

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("RESEARCH_KB_TEST_TMP")
        ) as tmp:
            dest = Path(tmp) / "out.pdf"
            result = download_pdf(
                "https://example.org/paper.pdf", dest, 1024, 30, "test-agent", opener
            )
        self.assertFalse(result["ok"])
        self.assertFalse(dest.exists())


class AcquisitionRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            dir=os.environ.get("RESEARCH_KB_TEST_TMP")
        )
        self.output = Path(self.temp.name) / "staging"
        self.output.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_run_writes_staging_manifest_and_manual_queue(self) -> None:
        opener = _FakeUrlOpener(_e2e_handler())
        result = run_acquisition(
            output=self.output,
            concept="Lukacs totality",
            sep_entries=["lukacs"],
            email="me@example.com",
            recent_max=3,
            max_downloads=10,
            timeout=30,
            user_agent="test-agent",
            urlopen=opener,
        )
        run_dir = Path(result["run_dir"])
        self.assertTrue(run_dir.is_dir())
        manifest = json.loads(
            (run_dir / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["worker"]["name"], WORKER_NAME)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["summary"]["sep_entries"], 1)
        self.assertEqual(manifest["summary"]["bibliography_items"], 3)
        self.assertEqual(manifest["summary"]["recent_works"], 1)
        self.assertEqual(manifest["summary"]["downloaded"], 3)
        self.assertEqual(manifest["summary"]["manual_queue"], 1)
        self.assertEqual(len(list((run_dir / "files").glob("*.pdf"))), 3)
        self.assertTrue(
            any(output["path"] == "report.md" for output in manifest["outputs"])
        )
        self.assertTrue(
            all(output["content_hash"] for output in manifest["outputs"])
        )
        manual = [
            json.loads(line)
            for line in (run_dir / "manual-queue.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        self.assertTrue(any("Western Marxism" in entry["title"] for entry in manual))
        sep_records = [
            json.loads(line)
            for line in (run_dir / "sep-entries.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        self.assertEqual(sep_records[0]["slug"], "lukacs")
        self.assertEqual(len(sep_records[0]["related_entries"]), 2)

    def test_max_items_limits_bibliography_processing(self) -> None:
        opener = _FakeUrlOpener(_e2e_handler())
        result = run_acquisition(
            output=self.output,
            sep_entries=["lukacs"],
            max_items=1,
            timeout=30,
            user_agent="test-agent",
            urlopen=opener,
        )
        self.assertEqual(result["summary"]["bibliography_items"], 1)
        self.assertTrue(any("truncated" in note for note in result["notes"]))

    def test_run_resolves_and_downloads_explicit_doi(self) -> None:
        def handler(url: str):
            if url.startswith("https://api.unpaywall.org/v2/10.1000/") and "email" in url:
                return _json_response(
                    {
                        "is_oa": True,
                        "title": "Lukacs and the Question of Totality",
                        "year": 2023,
                        "journal_name": "Historical Materialism",
                        "doi": "10.1000/crossref-work",
                        "z_authors": [{"given": "Gyorgy", "family": "Markus"}],
                        "best_oa_location": {
                            "url_for_pdf": "https://example.org/lukacs-totality.pdf",
                            "url": "https://example.org/lukacs-totality-landing",
                        },
                        "url": "https://example.org/lukacs-totality-landing",
                    }
                )
            if url.startswith("https://api.openalex.org/"):
                return _json_response({"results": []})
            if url.startswith("https://example.org/lukacs-totality.pdf"):
                return _FakeResponse(_PDF, "application/pdf")
            raise AssertionError("unexpected URL: " + url)

        opener = _FakeUrlOpener(handler)
        result = run_acquisition(
            output=self.output,
            dois=["10.1000/crossref-work"],
            email="me@example.com",
            max_downloads=10,
            timeout=30,
            user_agent="test-agent",
            urlopen=opener,
        )
        run_dir = Path(result["run_dir"])
        self.assertEqual(result["summary"]["downloaded"], 1)
        self.assertEqual(result["summary"]["manual_queue"], 0)
        manifest = json.loads(
            (run_dir / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["params"]["dois"], ["10.1000/crossref-work"])
        self.assertTrue((run_dir / "files" / "item_0001.pdf").exists())
        candidates = [
            json.loads(line)
            for line in (run_dir / "candidates.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        self.assertEqual(candidates[0]["source_kind"], "explicit_doi")
        self.assertEqual(candidates[0]["download"], "ok")
        self.assertEqual(
            candidates[0]["resolved"]["pdf_url"],
            "https://example.org/lukacs-totality.pdf",
        )

    def test_run_records_relaxed_ssl_download_note(self) -> None:
        def handler(url: str, request=None):
            if url.startswith("https://api.unpaywall.org/v2/10.1000/"):
                return _json_response(
                    {
                        "is_oa": True,
                        "title": "Lukacs and the Question of Totality",
                        "year": 2023,
                        "journal_name": "Historical Materialism",
                        "doi": "10.1000/crossref-work",
                        "z_authors": [{"given": "Gyorgy", "family": "Markus"}],
                        "best_oa_location": {
                            "url_for_pdf": "https://example.org/lukacs-totality.pdf",
                            "url": "https://example.org/lukacs-totality-landing",
                        },
                        "url": "https://example.org/lukacs-totality-landing",
                    }
                )
            if url.startswith("https://api.openalex.org/"):
                return _json_response({"results": []})
            if url.startswith("https://example.org/lukacs-totality.pdf"):
                context = getattr(request, "context", None)
                if context is None:
                    raise urllib.error.URLError(
                        ssl.SSLCertVerificationError(
                            1, "unable to get local issuer certificate"
                        )
                    )
                return _FakeResponse(_PDF, "application/pdf")
            raise AssertionError("unexpected URL: " + url)

        opener = _FakeUrlOpener(handler)
        result = run_acquisition(
            output=self.output,
            dois=["10.1000/crossref-work"],
            email="me@example.com",
            max_downloads=10,
            timeout=30,
            user_agent="test-agent",
            urlopen=opener,
        )
        run_dir = Path(result["run_dir"])
        self.assertEqual(result["summary"]["downloaded"], 1)
        candidates = [
            json.loads(line)
            for line in (run_dir / "candidates.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        self.assertEqual(candidates[0]["download"], "ok")
        self.assertEqual(
            candidates[0]["resolved"]["download_note"],
            "relaxed SSL retry succeeded",
        )

    def test_run_uses_crossref_when_openalex_recent_fails(self) -> None:
        def handler(url: str):
            if url.startswith("https://plato.stanford.edu/entries/lukacs/"):
                return _FakeResponse(_SEP_HTML, "text/html")
            if url.startswith("https://api.unpaywall.org/"):
                return urllib.error.URLError("blocked")
            if url.startswith("https://api.openalex.org/works?") and "publication_date" in url:
                return urllib.error.HTTPError(
                    url, 429, "Too Many Requests", {}, None
                )
            if url.startswith("https://api.openalex.org/works?") and "title.search" in url:
                if "Praxis" in urllib.parse.unquote(url):
                    return _json_response({"results": [_openalex_work()]})
                return _json_response({"results": []})
            if url.startswith("https://api.openalex.org/works?"):
                return _json_response({"results": []})
            if url.startswith("https://api.openalex.org/works/doi:"):
                return _json_response(_openalex_work())
            if url.startswith("https://api.crossref.org/works?") and "from-pub-date" in url:
                return _json_response(
                    {
                        "message": {
                            "items": [
                                _crossref_payload(
                                    DOI="10.1000/recent",
                                    title=["Recent Lukacs Studies"],
                                )["message"]
                            ]
                        }
                    }
                )
            if url.startswith("https://api.crossref.org/works"):
                return _json_response({"message": {"items": []}})
            if url.startswith("https://example.org/"):
                return _FakeResponse(_PDF, "application/pdf")
            raise AssertionError("unexpected URL: " + url)

        opener = _FakeUrlOpener(handler)
        with unittest.mock.patch("research_kb.acquisition.time.sleep"):
            result = run_acquisition(
                output=self.output,
                concept="Lukacs totality",
                sep_entries=["lukacs"],
                recent_max=3,
                max_downloads=10,
                timeout=30,
                user_agent="test-agent",
                urlopen=opener,
            )
        self.assertEqual(result["summary"]["recent_works"], 1)
        self.assertGreaterEqual(result["summary"]["downloaded"], 1)
        self.assertTrue(any("recent search returned" in note for note in result["notes"]))
        self.assertTrue(any("crossref_doi" in note for note in result["notes"]))


class RateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            dir=os.environ.get("RESEARCH_KB_TEST_TMP")
        )
        self.output = Path(self.temp.name) / "staging"
        self.output.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_run_completes_when_openalex_rate_limits(self) -> None:
        def handler(url: str):
            if url.startswith("https://plato.stanford.edu/entries/lukacs/"):
                return _FakeResponse(_SEP_HTML, "text/html")
            if url.startswith(
                (
                    "https://api.openalex.org/",
                    "https://api.unpaywall.org/",
                    "https://api.crossref.org/",
                )
            ):
                return urllib.error.HTTPError(
                    url, 429, "Too Many Requests", {}, None
                )
            raise AssertionError("unexpected URL: " + url)

        opener = _FakeUrlOpener(handler)
        with unittest.mock.patch("research_kb.acquisition.time.sleep"):
            result = run_acquisition(
                output=self.output,
                sep_entries=["lukacs"],
                timeout=30,
                user_agent="test-agent",
                urlopen=opener,
            )
        self.assertEqual(result["summary"]["manual_queue"], 3)
        self.assertTrue(any("429" in note for note in result["notes"]))


if __name__ == "__main__":
    unittest.main()
