"""Read-only storage duplicate check for research-kb.

Scans configured corpus roots plus user-supplied scan directories and reports:

1. files under scan directories whose SHA-256 matches a corpus file
   (project-level copies of canonical sources);
2. exact duplicate groups inside the scan directories themselves.

This module never deletes or moves anything; it only reports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

_CHUNK = 1 << 20


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _index_files(roots: list[Path]) -> tuple[dict[str, list[Path]], int]:
    """Return {sha256: [paths]} and total byte count for the given roots."""
    by_hash: dict[str, list[Path]] = defaultdict(list)
    total = 0
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                total += path.stat().st_size
                by_hash[_sha256(path)].append(path)
            except OSError:
                continue
    return by_hash, total


def run_storage_check(
    corpus_roots: list[Path],
    scan_roots: list[Path],
) -> dict:
    corpus_by_hash, corpus_bytes = _index_files(corpus_roots)
    scan_by_hash, scan_bytes = _index_files(scan_roots)

    corpus_duplicates: list[dict] = []
    internal_duplicates: list[dict] = []
    corpus_dup_bytes = 0
    internal_dup_bytes = 0

    for digest, paths in sorted(scan_by_hash.items()):
        if digest in corpus_by_hash:
            for path in paths:
                corpus_dup_bytes += path.stat().st_size
                corpus_duplicates.append(
                    {
                        "sha256": digest,
                        "path": str(path),
                        "size": path.stat().st_size,
                        "corpus_copy": str(corpus_by_hash[digest][0]),
                    }
                )
        elif len(paths) > 1:
            for path in paths[1:]:
                internal_dup_bytes += path.stat().st_size
            internal_duplicates.append(
                {
                    "sha256": digest,
                    "size": paths[0].stat().st_size,
                    "copies": len(paths),
                    "paths": [str(path) for path in paths],
                }
            )

    return {
        "ok": True,
        "corpus_files": sum(len(v) for v in corpus_by_hash.values()),
        "corpus_bytes": corpus_bytes,
        "scanned_files": sum(len(v) for v in scan_by_hash.values()),
        "scanned_bytes": scan_bytes,
        "corpus_duplicate_files": len(corpus_duplicates),
        "corpus_duplicate_bytes": corpus_dup_bytes,
        "corpus_duplicates": sorted(corpus_duplicates, key=lambda item: -item["size"]),
        "internal_duplicate_groups": len(internal_duplicates),
        "internal_duplicate_bytes": internal_dup_bytes,
        "internal_duplicates": sorted(internal_duplicates, key=lambda item: -item["size"]),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="research-kb storage-check",
        description="Read-only duplicate storage check against corpus roots.",
    )
    parser.add_argument("--corpus", action="append", default=None, help="Corpus root (defaults to config corpus_roots)")
    parser.add_argument("--scan", action="append", required=True, help="Directory to scan for duplicates")
    parser.add_argument("--config", default=None, help="Path to config.toml (for default corpus roots)")
    args = parser.parse_args(argv)

    corpus_roots = [Path(value) for value in (args.corpus or [])]
    if not corpus_roots:
        if not args.config:
            parser.error("either --corpus or --config is required")
        from .config import Settings

        settings = Settings.load(args.config)
        corpus_roots = list(settings.corpus_roots)

    report = run_storage_check(corpus_roots=corpus_roots, scan_roots=[Path(value) for value in args.scan])
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())