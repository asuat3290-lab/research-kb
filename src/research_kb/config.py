from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Limits:
    max_top_k: int = 20
    max_context_passages: int = 3
    max_query_chars: int = 1000
    max_return_chars: int = 16000
    max_searches_per_session: int = 100
    max_writes_per_session: int = 50
    verification_token_ttl_seconds: int = 900


@dataclass(frozen=True)
class Settings:
    config_path: Path
    root: Path
    database: Path
    corpus_roots: tuple[Path, ...]
    workspace: Path
    limits: Limits
    default_search_mode: str = "lexical"
    semantic_enabled: bool = False

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Settings":
        selected = Path(
            path or os.environ.get("RESEARCH_KB_CONFIG") or "config.toml"
        ).expanduser().resolve()
        with selected.open("rb") as handle:
            raw = tomllib.load(handle)
        root = selected.parent
        paths = raw.get("paths", {})
        limits = raw.get("limits", {})
        retrieval = raw.get("retrieval", {})

        def resolve(value: str) -> Path:
            candidate = Path(value).expanduser()
            return (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()

        corpus = tuple(resolve(value) for value in paths.get("corpus_roots", ["corpus"]))
        return cls(
            config_path=selected,
            root=root,
            database=resolve(paths.get("database", "data/research.db")),
            corpus_roots=corpus,
            workspace=resolve(paths.get("workspace", "workspace")),
            limits=Limits(**{key: int(value) for key, value in limits.items()}),
            default_search_mode=str(retrieval.get("default_mode", "lexical")),
            semantic_enabled=bool(retrieval.get("semantic_enabled", False)),
        )

