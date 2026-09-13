"""Append-oriented repository and control-plane invariants for MR-1.

The repository deliberately owns all SQLite writes.  There is no arbitrary
SQL method, no automatic initialization, and no path from a researcher-facing
MCP tool to this module.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from ...policy import Actor
from ..contract import (
    ApprovalConsumption,
    AcquisitionRequest,
    AttackRecord,
    CanonicalObject,
    CanonicalRelation,
    CanonicalObjectKind,
    Checkpoint,
    ClaimSnapshot,
    CompletionEvaluationInput,
    CompletionResult,
    ContractValidationError,
    ColdReviewPacket,
    ColdReviewResult,
    CoverageLedger,
    DiscussionSession,
    EvidenceSnapshot,
    FormalCompletionEvidence,
    Iteration,
    MaxResearchCharter,
    MaxRunState,
    MinorityReport,
    RehydrationInput,
    RehydrationOutput,
    ReportProjection,
    ResearchState,
    RunStatus,
    RunTransitionResult,
    SearchStrategy,
    SpeculativeIdea,
    ValidityAudit,
    StartApproval,
    WorkingState,
    allowed_run_transitions,
    canonical_json,
    canonical_sha256,
    charter_hash,
    evaluate_completion_result,
    make_event_id,
    make_claim_snapshot,
    make_evidence_snapshot,
    make_stable_id,
    model_to_dict,
    rebuild_research_state,
    rehydrate,
    source_policy_hash,
    transition_run_state,
    validate_canonical_object,
    validate_canonical_relation,
    validate_checkpoint,
    validate_checkpoint_lineage,
    validate_claim_evidence_trace,
    validate_completion_result,
    validate_iteration,
    validate_run_state,
    validate_start_approval,
    is_project_id,
    is_stable_id,
)
from .db import (
    CONTROL_SCHEMA_VERSION,
    MaxControlError,
    MaxControlNotInitialized,
    MaxResearchSettings,
    connect_control_db,
    control_transaction,
    initialize_control_db,
)
from .migrations import validate_migration_release, validate_schema_ledger
from .schema_manifest import SchemaManifestError, verify_schema_manifest
from .control_models import CanonicalChangeSet, UsageAuthority, UsageReceipt


_ISO = "%Y-%m-%dT%H:%M:%S.%fZ"
_ROUND_TYPES = {"exploration", "adjudication", "attack", "rehydration", "acquisition_review", "cold_review"}
_STATUSES = {"started", "completed", "aborted"}
_FORBIDDEN_PAYLOAD_KEYS = {
    "full_text", "source_text", "passage_text", "pdf_text", "raw_document", "api_key",
    "secret", "password", "access_token", "refresh_token",
}
_FORBIDDEN_PAYLOAD_FRAGMENTS = (
    "prompt", "raw_response", "source_text", "full_text", "passage_text",
    "pdf_text", "raw_document", "api_key", "secret", "password",
    "access_token", "refresh_token", "private_key", "model_key",
)
_SECRET_VALUE_RE = re.compile(r"(?:bearer\s+[A-Za-z0-9._~+/=-]{12,}|sk-[A-Za-z0-9_-]{12,}|api[-_ ]?key\s*[:=]|secret\s*[:=])", re.IGNORECASE)
_SOURCE_REF_KEYS = {
    "source_ref", "source_refs", "source_reference", "source_references",
    "verified_source_version_id", "verified_evidence_id",
}
_SOURCE_REF_ALLOWED = {
    "project_id", "document_id", "document_version_id", "passage_id", "verified_evidence_id",
    "verified_source_version_id", "reference_hash",
}
_SOURCE_REF_CLIENT_ALLOWED = _SOURCE_REF_ALLOWED - {"reference_hash"}
_BUDGET_ALIASES = {
    "iterations": "iteration_count", "iteration_count": "iteration_count", "max_iterations": "iteration_count",
    "wall_clock": "wall_clock_seconds", "wall_clock_seconds": "wall_clock_seconds", "max_wall_clock_seconds": "wall_clock_seconds",
    "input_tokens": "input_tokens", "max_input_tokens": "input_tokens",
    "output_tokens": "output_tokens", "max_output_tokens": "output_tokens",
    "cost_units": "cost_units", "monetary_cost_units": "cost_units", "max_cost_units": "cost_units",
    "acquisition_requests": "acquisition_requests", "max_acquisition_requests": "acquisition_requests",
    "acquisition_bytes": "acquisition_bytes", "max_acquisition_bytes": "acquisition_bytes",
}
_ABSOLUTE_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)")


class SourceReferenceResolver(Protocol):
    def resolve_reference(self, *, project_id: str, reference: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """Return server-owned stable IDs for a core reference or ``None``."""


Clock = Callable[[], datetime]


def _utc_now(clock: Clock | None = None) -> datetime:
    value = clock() if clock is not None else datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _timestamp(clock: Clock | None = None) -> str:
    return _utc_now(clock).strftime(_ISO)[:-3] + "Z"


def _parse_timestamp(value: str | None) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _loads(value: str) -> Any:
    return json.loads(value)


def _json(value: Any) -> str:
    return canonical_json(value)


def _hash(value: Any) -> str:
    return canonical_sha256(value)


def _actor_fields(actor: Actor) -> tuple[str, str, str, str]:
    return actor.actor_id, actor.actor_kind, actor.session_id, actor.framework


def _safe_error(exc: Exception) -> MaxControlError:
    if isinstance(exc, MaxControlError):
        return exc
    if isinstance(exc, ContractValidationError):
        return MaxControlError("Max control contract validation failed")
    if isinstance(exc, sqlite3.IntegrityError):
        return MaxControlError("Max control write conflicts with an existing immutable record")
    if isinstance(exc, sqlite3.OperationalError):
        return MaxControlError("Max control database is busy or unavailable")
    return MaxControlError("Max control operation failed")


def _walk_values(value: Any, path: str = "$") -> list[tuple[str, Any, str]]:
    found: list[tuple[str, Any, str]] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_string = str(key)
            item_path = f"{path}.{key_string}"
            found.append((key_string, item, item_path))
            found.extend(_walk_values(item, item_path))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(_walk_values(item, f"{path}[{index}]"))
    return found


def _reject_untrusted_payload(value: Any) -> None:
    def walk(item: Any, path: str, depth: int) -> None:
        if depth > 32:
            raise MaxControlError("control payload nesting is too deep")
        if isinstance(item, Mapping):
            if len(item) > 10_000:
                raise MaxControlError("control payload has too many fields")
            for key, child in item.items():
                key_text = str(key)
                lowered = key_text.casefold()
                if lowered in _FORBIDDEN_PAYLOAD_KEYS or any(fragment in lowered for fragment in _FORBIDDEN_PAYLOAD_FRAGMENTS):
                    raise MaxControlError("canonical payload contains prohibited source or secret material")
                walk(child, f"{path}.{key_text}", depth + 1)
        elif isinstance(item, (list, tuple)):
            if len(item) > 10_000:
                raise MaxControlError("control payload has too many items")
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]", depth + 1)
        elif isinstance(item, str):
            if _ABSOLUTE_PATH_RE.match(item):
                raise MaxControlError("control payload contains a prohibited absolute path")
            if _SECRET_VALUE_RE.search(item):
                raise MaxControlError("control payload contains a prohibited secret value")
            if len(item) > 1_000_000:
                raise MaxControlError("canonical payload exceeds the bounded control-plane size")

    walk(value, "$", 0)


def _round_type(kind: str) -> str:
    value = str(kind)
    if value in _ROUND_TYPES:
        return value
    if value in {"socratic_exploration", "targeted_retrieval", "state_update", "synthesis"}:
        return "exploration"
    if value == "adversarial_attack":
        return "attack"
    if value == "habermasian_adjudication":
        return "adjudication"
    if value == "rehydration_review":
        return "rehydration"
    if value == "acquisition_request":
        return "acquisition_review"
    if value == "cold_review":
        return "cold_review"
    raise MaxControlError("unsupported iteration round type")


def normalize_budget_limits(value: Mapping[str, Any]) -> dict[str, int | float]:
    if not isinstance(value, Mapping) or not value:
        raise MaxControlError("budget policy must be a non-empty object")
    normalized: dict[str, int | float] = {}
    for key, raw in value.items():
        unit = _BUDGET_ALIASES.get(str(key))
        if unit is None:
            raise MaxControlError("budget policy contains an unsupported unit")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(float(raw)) or raw < 0:
            raise MaxControlError("budget limits must be finite non-negative numbers")
        if unit in normalized and normalized[unit] != raw:
            raise MaxControlError("budget policy contains conflicting unit aliases")
        normalized[unit] = raw
    return dict(sorted(normalized.items()))


def normalize_budget_amount(value: Mapping[str, Any], *, allow_empty: bool = False) -> dict[str, int | float]:
    if not isinstance(value, Mapping) or (not value and not allow_empty):
        raise MaxControlError("budget amount must be a non-empty object")
    normalized: dict[str, int | float] = {}
    for key, raw in value.items():
        unit = _BUDGET_ALIASES.get(str(key), str(key) if str(key) in _BUDGET_ALIASES.values() else None)
        if unit is None:
            raise MaxControlError("budget amount contains an unsupported unit")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(float(raw)) or raw < 0:
            raise MaxControlError("budget amounts must be finite non-negative numbers")
        if raw == 0:
            continue
        if unit in normalized:
            normalized[unit] += raw
        else:
            normalized[unit] = raw
    if not normalized and not allow_empty:
        raise MaxControlError("budget amount must contain a positive unit")
    return dict(sorted(normalized.items()))


@dataclass(frozen=True)
class IterationRecordInput:
    iteration: Iteration | Mapping[str, Any]
    input_state_hash: str
    output_state_hash: str | None = None
    claim_snapshots: tuple[ClaimSnapshot | Mapping[str, Any], ...] = ()
    evidence_snapshots: tuple[EvidenceSnapshot | Mapping[str, Any], ...] = ()
    counterevidence_snapshots: tuple[EvidenceSnapshot | Mapping[str, Any], ...] = ()
    strategy_ledger: CoverageLedger | Mapping[str, Any] = CoverageLedger()
    record_refs: tuple[str, ...] = ()
    budget_delta: Mapping[str, Any] = None  # type: ignore[assignment]
    started_at: str | None = None
    finished_at: str | None = None

    def normalized(self) -> "IterationRecordInput":
        iteration = self.iteration if isinstance(self.iteration, Iteration) else Iteration.from_mapping(self.iteration)
        claims = tuple(item if isinstance(item, ClaimSnapshot) else ClaimSnapshot.from_mapping(item) for item in self.claim_snapshots)
        evidence = tuple(item if isinstance(item, EvidenceSnapshot) else EvidenceSnapshot.from_mapping(item) for item in self.evidence_snapshots)
        counter = tuple(item if isinstance(item, EvidenceSnapshot) else EvidenceSnapshot.from_mapping(item) for item in self.counterevidence_snapshots)
        ledger = self.strategy_ledger if isinstance(self.strategy_ledger, CoverageLedger) else CoverageLedger.from_mapping(self.strategy_ledger)
        delta = normalize_budget_amount(self.budget_delta or {}, allow_empty=True)
        return replace(self, iteration=iteration, claim_snapshots=claims, evidence_snapshots=evidence, counterevidence_snapshots=counter, strategy_ledger=ledger, record_refs=tuple(self.record_refs), budget_delta=delta)


class MaxControlRepository:
    """Repository for one independent Max control database."""

    def __init__(
        self,
        database: str | Path | MaxResearchSettings,
        *,
        clock: Clock | None = None,
        source_resolver: SourceReferenceResolver | Callable[..., Mapping[str, Any] | None] | None = None,
        usage_authority: UsageAuthority | None = None,
    ) -> None:
        self.settings = database if isinstance(database, MaxResearchSettings) else MaxResearchSettings.from_path(database)
        self.clock = clock
        self.source_resolver = source_resolver
        self.usage_authority = usage_authority

    def initialize(self, *, fixture: bool = False) -> dict[str, int | bool]:
        return initialize_control_db(self.settings, fixture=fixture)

    def is_fixture_database(self) -> bool:
        """Return true only for a database explicitly marked by ``max init``.

        The marker is intentionally server-created and append-only.  A caller
        cannot opt an arbitrary existing control database into fixture mode by
        merely selecting a fake adapter or supplying a matching-looking path.
        """

        connection = self._connect(read_only=True)
        try:
            row = connection.execute(
                "SELECT marker_json, marker_hash, fixture_identity, authority_id FROM max_fixture_control_markers WHERE marker_id='fixture-control-db'"
            ).fetchone()
            if row is None:
                return False
            marker = _loads(row["marker_json"])
            expected = {
                "marker_id": "fixture-control-db",
                "marker_kind": "fixture-control-db",
                "fixture_identity": "research-kb-mr2a-fixture/v1",
                "authority_id": "fixture-authority",
            }
            return marker == expected and row["marker_hash"] == _hash(expected) and row["fixture_identity"] == expected["fixture_identity"] and row["authority_id"] == expected["authority_id"]
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        finally:
            connection.close()

    def verify_database(self) -> dict[str, Any]:
        """Verify the whole control store without exposing its path or payloads."""

        connection = self._connect(read_only=True, verify_schema=False)
        try:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
            foreign_key_issues = [tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
            try:
                schema_manifest = verify_schema_manifest(connection)
            except Exception:
                schema_manifest = {"ok": False, "schema_version": CONTROL_SCHEMA_VERSION, "object_counts": {}, "issues": ["Max schema manifest verification failed"]}
            if not schema_manifest["ok"]:
                try:
                    from ..provider.store import ProviderStore
                    provider = ProviderStore(self).verify()
                except Exception:
                    provider = {
                        "ok": False,
                        "schema_version": CONTROL_SCHEMA_VERSION,
                        "issues": ["provider verification failed"],
                    }
                try:
                    from ..scheduler.worker import WorkerControl
                    worker = WorkerControl(self).verify()
                except Exception:
                    worker = {"ok": False, "run_id": None, "issues": ["worker control verification failed"]}
                try:
                    from ..scheduler.acquisition import AcquisitionControl
                    acquisition = AcquisitionControl(self).verify()
                except Exception:
                    acquisition = {"ok": False, "run_id": None, "issues": ["acquisition control verification failed"]}
                try:
                    from ..long_run import LongRunAuthorizationStore, SourceEgressStore
                    long_run = LongRunAuthorizationStore(self).verify()
                    source_egress = SourceEgressStore(self).verify()
                except Exception:
                    long_run = {"ok": False, "issues": ["long-run verification failed"]}
                    source_egress = {"ok": False, "issues": ["source-egress verification failed"]}
                try:
                    from ..external_agent import ExternalAgentService
                    external_agent = ExternalAgentService(self).verify()
                except Exception:
                    external_agent = {"ok": False, "issues": ["external-Agent verification failed"]}
                return {
                    "ok": False,
                    "schema_version": CONTROL_SCHEMA_VERSION,
                    "quick_check": quick_check == "ok",
                    "foreign_keys": not foreign_key_issues,
                    "run_count": 0,
                    "orphan_canonical_versions": 0,
                    "orphan_canonical_relations": 0,
                    "runs": {},
                    "provider": provider,
                    "worker": worker,
                    "acquisition": acquisition,
                    "long_run": long_run,
                    "source_egress": source_egress,
                    "external_agent": external_agent,
                    "schema_manifest": schema_manifest,
                    "issues": list(schema_manifest.get("issues", ())),
                }
            schema_versions = [
                int(row[0])
                for row in connection.execute("SELECT version FROM max_schema_migrations ORDER BY version")
            ]
            run_ids = [row[0] for row in connection.execute("SELECT run_id FROM max_runs ORDER BY run_id")]
            orphan_objects = connection.execute("SELECT COUNT(*) FROM max_canonical_object_versions v WHERE NOT EXISTS (SELECT 1 FROM max_run_object_memberships m WHERE m.version_id=v.version_id)").fetchone()[0]
            orphan_relations = connection.execute("SELECT COUNT(*) FROM max_canonical_relations r WHERE NOT EXISTS (SELECT 1 FROM max_run_relation_memberships m WHERE m.relation_id=r.relation_id)").fetchone()[0]
        finally:
            connection.close()
        runs: dict[str, dict[str, Any]] = {}
        for run_id in run_ids:
            try:
                runs[run_id] = self.verify_run(run_id=run_id)
            except MaxControlError:
                runs[run_id] = {"ok": False, "issues": ["run verification failed"]}
        try:
            from ..provider.store import ProviderStore
            provider = ProviderStore(self).verify()
        except Exception:
            provider = {"ok": False, "schema_version": CONTROL_SCHEMA_VERSION, "issues": ["provider verification failed"]}
        try:
            from ..scheduler.worker import WorkerControl
            worker = WorkerControl(self).verify()
        except Exception:
            worker = {"ok": False, "run_id": None, "issues": ["worker control verification failed"]}
        try:
            from ..scheduler.acquisition import AcquisitionControl
            acquisition = AcquisitionControl(self).verify()
        except Exception:
            acquisition = {"ok": False, "run_id": None, "issues": ["acquisition control verification failed"]}
        try:
            from ..long_run import LongRunAuthorizationStore, SourceEgressStore
            long_run = LongRunAuthorizationStore(self).verify()
            source_egress = SourceEgressStore(self).verify()
        except Exception:
            long_run = {"ok": False, "run_id": run_id, "issues": ["long-run verification failed"]}
            source_egress = {"ok": False, "run_id": run_id, "issues": ["source-egress verification failed"]}
        try:
            from ..external_agent import ExternalAgentService
            external_agent = ExternalAgentService(self).verify()
        except Exception:
            external_agent = {"ok": False, "issues": ["external-Agent verification failed"]}
        issues: list[str] = []
        if quick_check != "ok":
            issues.append("SQLite quick_check failed")
        if foreign_key_issues:
            issues.append("SQLite foreign_key_check failed")
        if schema_versions != list(range(1, CONTROL_SCHEMA_VERSION + 1)):
            issues.append("Max control-plane migration history is not contiguous")
        if not schema_manifest.get("ok", False):
            issues.extend(str(item) for item in schema_manifest.get("issues", ()))
        if any(not item.get("ok", False) for item in runs.values()):
            issues.append("one or more Max runs failed verification")
        if orphan_objects or orphan_relations:
            issues.append("canonical versions or relations lack explicit Run membership")
        if not provider.get("ok", False):
            issues.append("provider control-plane verification failed")
        if not worker.get("ok", False):
            issues.append("worker control-plane verification failed")
        if not acquisition.get("ok", False):
            issues.append("acquisition control-plane verification failed")
        if not long_run.get("ok", False):
            issues.append("long-run control-plane verification failed")
        if not source_egress.get("ok", False):
            issues.append("source-egress control-plane verification failed")
        if not external_agent.get("ok", False):
            issues.append("external-Agent control-plane verification failed")
        return {
            "ok": not issues,
            "schema_version": CONTROL_SCHEMA_VERSION,
            "quick_check": quick_check == "ok",
            "foreign_keys": not foreign_key_issues,
            "run_count": len(run_ids),
            "orphan_canonical_versions": int(orphan_objects),
            "orphan_canonical_relations": int(orphan_relations),
            "runs": runs,
            "provider": provider,
            "worker": worker,
            "acquisition": acquisition,
            "long_run": long_run,
            "source_egress": source_egress,
            "external_agent": external_agent,
            "schema_manifest": schema_manifest,
            "issues": issues,
        }

    def backup(self, destination: str | Path) -> dict[str, Any]:
        """Create a new SQLite backup and verify its reconstructed control facts."""

        target = MaxResearchSettings.from_path(destination).database
        if target == self.settings.database:
            raise MaxControlError("backup destination must differ from the control database")
        if target.exists():
            raise MaxControlError("backup destination already exists")
        if not target.parent.is_dir():
            raise MaxControlError("backup destination parent directory does not exist")
        source = self._connect(read_only=True, verify_schema=False)
        copied: sqlite3.Connection | None = None
        try:
            source_schema = verify_schema_manifest(source)
            if not source_schema["ok"]:
                raise MaxControlError("control database backup source failed schema verification")
            copied = connect_control_db(target, read_only=False)
            source.backup(copied)
            copied.commit()
        except Exception as exc:
            raise _safe_error(exc) from exc
        finally:
            source.close()
            if copied is not None:
                copied.close()
        verification = MaxControlRepository(target, clock=self.clock).verify_database()
        if not verification["ok"]:
            raise MaxControlError("control database backup failed verification")
        return {
            "created": True,
            "schema_version": CONTROL_SCHEMA_VERSION,
            "size_bytes": target.stat().st_size,
            "verification": verification,
        }

    def restore(self, source: str | Path) -> dict[str, Any]:
        """Restore a new control database from a verified SQLite backup."""

        source_path = MaxResearchSettings.from_path(source).database
        target = self.settings.database
        if source_path == target:
            raise MaxControlError("restore source must differ from the target control database")
        if not source_path.is_file():
            raise MaxControlNotInitialized("restore source database is not available")
        if target.exists():
            raise MaxControlError("restore target already exists")
        if not target.parent.is_dir():
            raise MaxControlError("restore target parent directory does not exist")
        source_repo = MaxControlRepository(source_path, clock=self.clock)
        source_verification = source_repo.verify_database()
        if not source_verification["ok"]:
            raise MaxControlError("restore source failed control-plane verification")
        source_connection = source_repo._connect(read_only=True)
        copied: sqlite3.Connection | None = None
        try:
            copied = connect_control_db(target, read_only=False)
            source_connection.backup(copied)
            copied.commit()
        except Exception as exc:
            raise _safe_error(exc) from exc
        finally:
            source_connection.close()
            if copied is not None:
                copied.close()
        verification = self.verify_database()
        if not verification["ok"]:
            raise MaxControlError("restored control database failed verification")
        return {
            "restored": True,
            "schema_version": CONTROL_SCHEMA_VERSION,
            "size_bytes": target.stat().st_size,
            "verification": verification,
        }

    def _connect(self, *, read_only: bool, verify_schema: bool = True) -> sqlite3.Connection:
        if not read_only and not self.settings.database.is_file():
            raise MaxControlNotInitialized("Max control database is not initialized; run max init explicitly")
        connection = connect_control_db(self.settings, read_only=read_only)
        try:
            validate_migration_release()
            schema_versions = validate_schema_ledger(connection, require_current=False)
            if not schema_versions:
                raise RuntimeError("Max control migration ledger is unavailable")
            if schema_versions[-1] < CONTROL_SCHEMA_VERSION:
                if not read_only:
                    raise MaxControlError("legacy Max control schema is read-only; create an explicit migrated copy")
                # Schema-19 Preview/Authority history remains inspectable, but
                # is never auto-upgraded or treated as a dev9 Snapshot.
                return connection
            if schema_versions != tuple(range(1, CONTROL_SCHEMA_VERSION + 1)):
                raise RuntimeError("Max control database schema is not current")
            if verify_schema:
                schema_check = verify_schema_manifest(connection)
                if not schema_check["ok"]:
                    raise MaxControlError("Max control database schema manifest verification failed")
        except (MaxControlError, Exception) as exc:
            connection.close()
            if isinstance(exc, MaxControlError):
                raise
            raise MaxControlError("Max control database schema verification failed") from exc
        return connection

    def _run_row(self, connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM max_runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise MaxControlError("Max run was not found")
        return row

    def _run_state(self, row: sqlite3.Row) -> MaxRunState:
        try:
            value = MaxRunState.from_mapping(_loads(row["run_state_json"]))
        except Exception as exc:
            raise MaxControlError("stored Max Run State is invalid") from exc
        return value

    def _charter(self, row: sqlite3.Row) -> MaxResearchCharter:
        try:
            value = MaxResearchCharter.from_mapping(_loads(row["charter_json"]))
        except Exception as exc:
            raise MaxControlError("stored Charter is invalid") from exc
        return value

    def _require_project_run(self, row: sqlite3.Row, project_id: str) -> None:
        if row["project_id"] != project_id:
            raise MaxControlError("run is outside the requested project boundary")

    def _update_run(self, connection: sqlite3.Connection, state: MaxRunState, *, now: str, completion: CompletionResult | None = None) -> None:
        result_json = _json(completion) if completion is not None else None
        result_hash = _hash(completion) if completion is not None else None
        connection.execute(
            """
            UPDATE max_runs SET status=?, current_state_hash=?, current_checkpoint_id=?,
                state_version=?, iteration_index=?, completion_result_id=?, completion_state_hash=?,
                run_state_json=?, updated_at=?,
                completion_result_json=COALESCE(?, completion_result_json),
                completion_result_hash=COALESCE(?, completion_result_hash)
            WHERE run_id=?
            """,
            (
                getattr(state.status, "value", state.status), state.current_state_hash, state.current_checkpoint_id,
                state.state_version, state.iteration_index, state.completion_result_id, state.completion_state_hash,
                _json(state), now, result_json, result_hash, state.run_id,
            ),
        )

    def _record_transition_result(
        self,
        connection: sqlite3.Connection,
        *,
        prior: MaxRunState,
        transition: RunTransitionResult,
        actor: Actor,
        now: str,
    ) -> dict[str, Any]:
        """Persist the MR-0B transition value in the same transaction as state mutation."""

        new_state = transition.new_state
        transition_json = _json(transition)
        transition_hash = _hash(transition)
        transition_id = make_event_id(
            "run_transition_result",
            prior.project_id,
            {
                "run_id": prior.run_id,
                "prior_state_version": prior.state_version,
                "resulting_state_version": new_state.state_version,
                "transition_hash": transition_hash,
            },
        )
        connection.execute(
            """
            INSERT INTO max_run_transition_results(
                transition_id, run_id, prior_state_version, resulting_state_version,
                from_status, to_status, transition_json, transition_hash, created_at,
                actor_id, actor_kind, session_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transition_id,
                prior.run_id,
                prior.state_version,
                new_state.state_version,
                str(getattr(prior.status, "value", prior.status)),
                str(getattr(new_state.status, "value", new_state.status)),
                transition_json,
                transition_hash,
                now,
                actor.actor_id,
                actor.actor_kind,
                actor.session_id,
            ),
        )
        return {
            "transition_id": transition_id,
            "prior_state_version": prior.state_version,
            "resulting_state_version": new_state.state_version,
            "from_status": str(getattr(prior.status, "value", prior.status)),
            "to_status": str(getattr(new_state.status, "value", new_state.status)),
            "transition_hash": transition_hash,
        }

    def _append_event(self, connection: sqlite3.Connection, *, run_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str) -> dict[str, Any]:
        _reject_untrusted_payload(payload)
        previous = connection.execute(
            "SELECT sequence_no, event_hash FROM max_events WHERE run_id=? ORDER BY sequence_no DESC LIMIT 1", (run_id,)
        ).fetchone()
        sequence = int(previous["sequence_no"]) + 1 if previous else 1
        previous_hash = str(previous["event_hash"]) if previous else ""
        payload_json = _json(payload)
        payload_hash = _hash(payload)
        event_identity = {"run_id": run_id, "sequence_no": sequence, "event_type": event_type, "payload_hash": payload_hash, "previous_event_hash": previous_hash}
        event_id = make_event_id("event", str(connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (run_id,)).fetchone()[0]), event_identity)
        event_hash = _hash({"event_id": event_id, **event_identity, "payload_json": payload_json, "actor_id": actor.actor_id, "actor_kind": actor.actor_kind, "session_id": actor.session_id, "created_at": now})
        connection.execute(
            """
            INSERT INTO max_events(event_id, run_id, sequence_no, event_type, payload_json, payload_hash,
                previous_event_hash, event_hash, actor_id, actor_kind, session_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, run_id, sequence, event_type, payload_json, payload_hash, previous_hash, event_hash, actor.actor_id, actor.actor_kind, actor.session_id, now),
        )
        return {"event_id": event_id, "sequence_no": sequence, "event_type": event_type, "event_hash": event_hash}

    def _resolve_sources(self, project_id: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        raw_refs: list[Mapping[str, Any]] = []
        scalar_refs: list[tuple[str, str]] = []
        for key, value, _ in _walk_values(payload):
            lowered = key.casefold()
            if lowered in {"source_refs", "source_references"}:
                if not isinstance(value, (list, tuple)):
                    raise MaxControlError("source references must be a list")
                for item in value:
                    if not isinstance(item, Mapping):
                        raise MaxControlError("source references must be objects")
                    raw_refs.append(item)
            elif lowered in {"source_ref", "source_reference"}:
                if not isinstance(value, Mapping):
                    raise MaxControlError("source reference must be an object")
                raw_refs.append(value)
            elif lowered in {"verified_source_version_id", "verified_evidence_id"} and isinstance(value, str):
                scalar_refs.append((lowered, value))
        raw_refs.extend({key: value} for key, value in scalar_refs)
        if not raw_refs:
            return []
        if self.source_resolver is None:
            raise MaxControlError("a server-owned core source resolver is required for source references")
        resolved: list[dict[str, Any]] = []
        for ref in raw_refs:
            unknown = set(str(key) for key in ref) - _SOURCE_REF_CLIENT_ALLOWED
            if unknown:
                raise MaxControlError("client citation metadata is not accepted as a source reference")
            if ref.get("project_id") not in (None, project_id):
                raise MaxControlError("source reference crosses project boundary")
            if not any(isinstance(ref.get(key), str) and ref.get(key) for key in _SOURCE_REF_CLIENT_ALLOWED - {"project_id"}):
                raise MaxControlError("source reference must contain a stable server-owned ID")
            try:
                if hasattr(self.source_resolver, "resolve_reference"):
                    answer = self.source_resolver.resolve_reference(project_id=project_id, reference=dict(ref))  # type: ignore[attr-defined]
                else:
                    answer = self.source_resolver(project_id=project_id, reference=dict(ref))  # type: ignore[misc]
            except Exception as exc:
                raise MaxControlError("core source reference validation failed") from exc
            if not isinstance(answer, Mapping) or answer.get("project_id") != project_id:
                raise MaxControlError("core source reference was not validated for this project")
            unknown_answer = set(str(key) for key in answer) - _SOURCE_REF_ALLOWED
            if unknown_answer:
                raise MaxControlError("source resolver returned unsupported metadata")
            normalized = dict(answer)
            for key in _SOURCE_REF_CLIENT_ALLOWED - {"project_id"}:
                if key in ref and key in normalized and ref[key] != normalized[key]:
                    raise MaxControlError("source resolver changed a client source ID")
            normalized.pop("reference_hash", None)
            normalized["reference_hash"] = _hash({"project_id": project_id, "reference": normalized})
            resolved.append(normalized)
        return sorted(resolved, key=_json)

    def _object_rows(self, connection: sqlite3.Connection, project_id: str, run_id: str) -> tuple[CanonicalObject, ...]:
        values: list[CanonicalObject] = []
        run = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
        if run is None or run["project_id"] != project_id:
            raise MaxControlError("canonical object query is outside the Run boundary")
        for row in connection.execute("SELECT v.object_json FROM max_canonical_object_versions v JOIN max_run_object_memberships m ON m.version_id=v.version_id WHERE m.run_id=? AND m.project_id=? ORDER BY v.stable_id, v.version", (run_id, project_id)):
            try:
                values.append(CanonicalObject.from_mapping(_loads(row[0])))
            except Exception as exc:
                raise MaxControlError("stored canonical object is invalid") from exc
        return tuple(values)

    def _relation_rows(self, connection: sqlite3.Connection, project_id: str, run_id: str) -> tuple[CanonicalRelation, ...]:
        values: list[CanonicalRelation] = []
        run = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
        if run is None or run["project_id"] != project_id:
            raise MaxControlError("canonical relation query is outside the Run boundary")
        for row in connection.execute("SELECT r.relation_json FROM max_canonical_relations r JOIN max_run_relation_memberships m ON m.relation_id=r.relation_id WHERE m.run_id=? AND m.project_id=? ORDER BY r.relation_id", (run_id, project_id)):
            try:
                values.append(CanonicalRelation.from_mapping(_loads(row[0])))
            except Exception as exc:
                raise MaxControlError("stored canonical relation is invalid") from exc
        return tuple(values)

    def _rebuild_state(self, connection: sqlite3.Connection, *, project_id: str, run_id: str | None) -> ResearchState:
        try:
            if run_id is None:
                raise MaxControlError("Research State rebuild requires an explicit Run")
            return rebuild_research_state(self._object_rows(connection, project_id, run_id), self._relation_rows(connection, project_id, run_id), project_id=project_id, run_id=run_id)
        except Exception as exc:
            raise _safe_error(exc) from exc

    def _save_state(self, connection: sqlite3.Connection, state: ResearchState, *, actor: Actor, now: str, rehydration_input_hash: str | None = None, rehydration_output_hash: str | None = None, drift: Sequence[str] = ()) -> None:
        connection.execute(
            """
            INSERT INTO max_research_states(run_id, project_id, state_hash, state_json, canonical_frontier_json,
                working_state_json, rehydration_input_hash, rehydration_output_hash, drift_json, updated_at, actor_id, actor_session)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET project_id=excluded.project_id, state_hash=excluded.state_hash,
                state_json=excluded.state_json, canonical_frontier_json=excluded.canonical_frontier_json,
                working_state_json=excluded.working_state_json, rehydration_input_hash=excluded.rehydration_input_hash,
                rehydration_output_hash=excluded.rehydration_output_hash, drift_json=excluded.drift_json,
                updated_at=excluded.updated_at, actor_id=excluded.actor_id, actor_session=excluded.actor_session
            """,
            (state.run_id, state.project_id, state.state_hash, _json(state), _json(sorted(state.latest_by_id)), _json({"canonical_object_ids": sorted(state.latest_by_id), "active_leading_hypothesis_id": state.active_leading_hypothesis_id}), rehydration_input_hash, rehydration_output_hash, _json(tuple(drift)), now, actor.actor_id, actor.session_id),
        )

    def _set_state_hash(self, connection: sqlite3.Connection, row: sqlite3.Row, state_hash: str, *, actor: Actor, now: str) -> MaxRunState:
        current = self._run_state(row)
        updated = replace(current, current_state_hash=state_hash, state_version=current.state_version + 1)
        validate_run_state(updated).raise_if_invalid()
        self._update_run(connection, updated, now=now)
        self._record_transition_result(connection, prior=current, transition=RunTransitionResult(updated), actor=actor, now=now)
        return updated

    def _add_object_membership(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        obj: CanonicalObject,
        actor: Actor,
        now: str,
        change_set_id: str | None = None,
    ) -> dict[str, Any]:
        row = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None or row["project_id"] != obj.project_id:
            raise MaxControlError("canonical object membership crosses the Run project boundary")
        version = connection.execute("SELECT version_id, project_id FROM max_canonical_object_versions WHERE version_id=?", (obj.version_id,)).fetchone()
        if version is None or version["project_id"] != obj.project_id:
            raise MaxControlError("canonical object version is not available for membership")
        membership_hash = _hash({"run_id": run_id, "project_id": obj.project_id, "version_id": obj.version_id, "change_set_id": change_set_id})
        connection.execute(
            "INSERT INTO max_run_object_memberships(run_id, project_id, version_id, adopted_by_change_set_id, adopted_at, actor_id, actor_kind, actor_session, membership_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, obj.project_id, obj.version_id, change_set_id, now, actor.actor_id, actor.actor_kind, actor.session_id, membership_hash),
        )
        return {"run_id": run_id, "version_id": obj.version_id, "membership_hash": membership_hash}

    def _add_relation_membership(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        relation: CanonicalRelation,
        actor: Actor,
        now: str,
        change_set_id: str | None = None,
    ) -> dict[str, Any]:
        row = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None or row["project_id"] != relation.project_id:
            raise MaxControlError("canonical relation membership crosses the Run project boundary")
        endpoints = connection.execute(
            "SELECT COUNT(*) FROM max_run_object_memberships WHERE run_id=? AND version_id IN (?, ?)",
            (run_id, relation.source_version_id, relation.target_version_id),
        ).fetchone()[0]
        if endpoints != 2:
            raise MaxControlError("relation endpoints must already belong to the target Run")
        relation_row = connection.execute("SELECT project_id FROM max_canonical_relations WHERE relation_id=?", (relation.relation_id,)).fetchone()
        if relation_row is None or relation_row["project_id"] != relation.project_id:
            raise MaxControlError("canonical relation is not available for membership")
        membership_hash = _hash({"run_id": run_id, "project_id": relation.project_id, "relation_id": relation.relation_id, "change_set_id": change_set_id})
        connection.execute(
            "INSERT INTO max_run_relation_memberships(run_id, project_id, relation_id, adopted_by_change_set_id, adopted_at, actor_id, actor_kind, actor_session, membership_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, relation.project_id, relation.relation_id, change_set_id, now, actor.actor_id, actor.actor_kind, actor.session_id, membership_hash),
        )
        return {"run_id": run_id, "relation_id": relation.relation_id, "membership_hash": membership_hash}

    def _assert_fence(self, connection: sqlite3.Connection, *, run_id: str, actor: Actor, fencing_token: int | None, now: str) -> None:
        if fencing_token is None:
            raise MaxControlError("a current lease fencing token is required for this write")
        row = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
        if row is None or row["owner_id"] != actor.actor_id or row["session_id"] != actor.session_id or int(row["fencing_token"]) != int(fencing_token):
            raise MaxControlError("stale or foreign lease fencing token")
        expiry = _parse_timestamp(row["expires_at"])
        if expiry is None or expiry <= _utc_now(self.clock):
            raise MaxControlError("lease has expired")

    def _insert_object(self, connection: sqlite3.Connection, obj: CanonicalObject, *, actor: Actor, now: str, run_id: str | None = None, change_set_id: str | None = None) -> CanonicalObject:
        validate_canonical_object(obj).raise_if_invalid()
        _reject_untrusted_payload(obj.payload)
        resolved_sources = self._resolve_sources(obj.project_id, obj.payload)
        identity = connection.execute(
            "SELECT kind FROM max_canonical_objects WHERE project_id=? AND stable_id=?",
            (obj.project_id, obj.stable_id),
        ).fetchone()
        kind_value = str(getattr(obj.kind, "value", obj.kind))
        if identity is None:
            connection.execute(
                "INSERT INTO max_canonical_objects(project_id, stable_id, kind, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?)",
                (obj.project_id, obj.stable_id, kind_value, now, actor.actor_id, actor.session_id),
            )
        elif identity["kind"] != kind_value:
            raise MaxControlError("canonical identity kind cannot change")
        previous = connection.execute(
            "SELECT version_id, version, kind FROM max_canonical_object_versions WHERE project_id=? AND stable_id=? ORDER BY version DESC LIMIT 1",
            (obj.project_id, obj.stable_id),
        ).fetchone()
        if previous is None:
            if obj.version != 1 or obj.supersedes_version_id is not None:
                raise MaxControlError("first canonical version must be version 1 without a predecessor")
        else:
            if obj.version != int(previous["version"]) + 1 or obj.supersedes_version_id != previous["version_id"] or kind_value != str(previous["kind"]):
                raise MaxControlError("canonical successor must immediately supersede the stored version")
        connection.execute(
            """
            INSERT INTO max_canonical_object_versions(version_id, project_id, stable_id, kind, version, supersedes_version_id,
                object_json, payload_hash, source_reference_json, source_reference_hash, created_at, actor_id, actor_session)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (obj.version_id, obj.project_id, obj.stable_id, str(getattr(obj.kind, "value", obj.kind)), obj.version, obj.supersedes_version_id, _json(obj), _hash(obj.payload), _json(resolved_sources), _hash(resolved_sources), now, actor.actor_id, actor.session_id),
        )
        if run_id is not None:
            self._add_object_membership(connection, run_id=run_id, obj=obj, actor=actor, now=now, change_set_id=change_set_id)
        return obj

    def _insert_relation(self, connection: sqlite3.Connection, relation: CanonicalRelation, *, actor: Actor, now: str, run_id: str | None = None, change_set_id: str | None = None) -> CanonicalRelation:
        validate_canonical_relation(relation).raise_if_invalid()
        source = connection.execute("SELECT stable_id, project_id FROM max_canonical_object_versions WHERE version_id=?", (relation.source_version_id,)).fetchone()
        target = connection.execute("SELECT stable_id, project_id FROM max_canonical_object_versions WHERE version_id=?", (relation.target_version_id,)).fetchone()
        if source is None or target is None or source["stable_id"] != relation.source_id or target["stable_id"] != relation.target_id or source["project_id"] != relation.project_id or target["project_id"] != relation.project_id:
            raise MaxControlError("relation endpoint version is missing or crosses the project boundary")
        connection.execute(
            """
            INSERT INTO max_canonical_relations(relation_id, project_id, source_id, source_version_id, target_id, target_version_id,
                relation_kind, relation_json, metadata_hash, created_at, actor_id, actor_session)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (relation.relation_id, relation.project_id, relation.source_id, relation.source_version_id, relation.target_id, relation.target_version_id, relation.relation, _json(relation), _hash(relation.metadata), now, actor.actor_id, actor.session_id),
        )
        if run_id is not None:
            self._add_relation_membership(connection, run_id=run_id, relation=relation, actor=actor, now=now, change_set_id=change_set_id)
        return relation

    def propose(self, *, project_id: str, charter: MaxResearchCharter | Mapping[str, Any], actor: Actor) -> dict[str, Any]:
        if not is_project_id(project_id):
            raise MaxControlError("project_id is invalid")
        try:
            value = charter if isinstance(charter, MaxResearchCharter) else MaxResearchCharter.from_mapping(charter)
            from ..contract import require_valid_charter
            value = require_valid_charter(value)
            # Normalize and validate the Charter budget before deriving any
            # hashes or opening the control database.  Provider/runner caps
            # and human approval ceilings belong to their later authorities;
            # an unsupported field must therefore fail with zero writes.
            value = replace(value, budget=normalize_budget_limits(value.budget))
        except Exception as exc:
            raise _safe_error(exc) from exc
        now = _timestamp(self.clock)
        c_hash = charter_hash(value)
        p_hash = source_policy_hash(value.source_policy)
        b_hash = _hash(value.budget)
        run_id = make_event_id("run", project_id, {"charter_hash": c_hash, "model_identity": value.model_identity, "created_at": now, "nonce": uuid.uuid4().hex})
        question_id = make_stable_id("research_question", _hash({"project_id": project_id, "question": value.question})[:48])
        question = CanonicalObject(stable_id=question_id, kind=CanonicalObjectKind.RESEARCH_QUESTION, project_id=project_id, payload={"question": value.question, "status": "active", "origin": "charter"})
        state = rebuild_research_state((question,), (), project_id=project_id, run_id=run_id)
        working = WorkingState(project_id, run_id, 0, value.budget, (question_id,), (), (), None, (), (), (), "")
        checkpoint = Checkpoint(project_id, run_id, working, value.budget, 0, (question_id,), checkpoint_id=make_event_id("checkpoint", project_id, {"run_id": run_id, "version": 1, "frontier": [question_id]}), supersedes_item_id=None, created_at=now, checkpoint_version=1)
        initial = MaxRunState(run_id=run_id, project_id=project_id, status=RunStatus.AWAITING_START_APPROVAL, charter_hash=c_hash, model_identity=value.model_identity, budget=value.budget, source_policy_hash=p_hash, state_version=1, current_state_hash=state.state_hash, current_checkpoint_id=checkpoint.checkpoint_id, budget_snapshot_hash=b_hash)
        validate_run_state(initial).raise_if_invalid()
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                connection.execute(
                    """
                    INSERT INTO max_runs(run_id, project_id, status, charter_json, charter_hash, model_identity,
                        source_policy_json, source_policy_hash, budget_policy_json, budget_hash, current_state_hash,
                        current_checkpoint_id, state_version, iteration_index, completion_result_id, completion_state_hash,
                        run_state_json, created_at, updated_at, actor_id, actor_session, completion_result_json, completion_result_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (run_id, project_id, initial.status.value, _json(value), c_hash, value.model_identity, _json(value.source_policy), p_hash, _json(value.budget), b_hash, state.state_hash, checkpoint.checkpoint_id, initial.state_version, initial.iteration_index, _json(initial), now, now, actor.actor_id, actor.session_id),
                )
                self._insert_object(connection, question, actor=actor, now=now, run_id=run_id)
                self._save_state(connection, state, actor=actor, now=now)
                connection.execute(
                    "INSERT INTO max_checkpoints(checkpoint_id, run_id, project_id, checkpoint_version, lineage_version, supersedes_item_id, state_hash, checkpoint_json, fencing_token, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, 1, ?, ?, ?)",
                    (checkpoint.checkpoint_id, run_id, project_id, checkpoint.checkpoint_version, 1, state.state_hash, _json(checkpoint), now, actor.actor_id, actor.session_id),
                )
                connection.execute("INSERT INTO max_checkpoint_current(run_id, checkpoint_id, set_at) VALUES (?, ?, ?)", (run_id, checkpoint.checkpoint_id, now))
                connection.execute("INSERT INTO max_leases(run_id, fencing_token) VALUES (?, 0)", (run_id,))
                self._append_event(connection, run_id=run_id, event_type="run_proposed", payload={"project_id": project_id, "charter_hash": c_hash, "model_identity": value.model_identity, "state_hash": state.state_hash}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="canonical_version_appended", payload={"version_id": question.version_id, "stable_id": question.stable_id, "kind": str(getattr(question.kind, "value", question.kind))}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="canonical_membership_added", payload={"version_id": question.version_id, "membership_kind": "object", "reason": "run_proposal"}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="checkpoint_created", payload={"checkpoint_id": checkpoint.checkpoint_id, "checkpoint_version": 1, "state_hash": state.state_hash}, actor=actor, now=now)
            return self._run_summary_from_state(initial, charter=value)
        except Exception as exc:
            if isinstance(exc, MaxControlError):
                raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def _run_summary_from_state(self, state: MaxRunState, *, charter: MaxResearchCharter | None = None) -> dict[str, Any]:
        return {
            "run_id": state.run_id, "project_id": state.project_id, "status": getattr(state.status, "value", state.status),
            "charter_hash": state.charter_hash, "model_identity": state.model_identity,
            "source_policy_hash": state.source_policy_hash, "budget_hash": _hash(state.budget),
            "state_version": state.state_version, "current_state_hash": state.current_state_hash,
            "current_checkpoint_id": state.current_checkpoint_id,
            "approval_id": state.approval_id, "approval_consumption_id": state.approval_consumption_id,
        }

    def get_run(self, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            row = self._run_row(connection, run_id)
            state = self._run_state(row)
            if state.charter_hash != row["charter_hash"] or _hash(state.budget) != row["budget_hash"]:
                raise MaxControlError("stored Run State binding is inconsistent")
            return self._run_summary_from_state(state)
        finally:
            connection.close()

    def approve(self, *, run_id: str, charter_hash_value: str, reason: str, actor: Actor, ttl_seconds: int = 3600) -> dict[str, Any]:
        if not actor.is_admin:
            raise MaxControlError("approval requires explicit human admin authority")
        if not reason or not reason.strip():
            raise MaxControlError("approval reason is required")
        if ttl_seconds < 1 or ttl_seconds > 86_400:
            raise MaxControlError("approval expiry is outside the supported range")
        now_dt = _utc_now(self.clock); now = _timestamp(self.clock); expires = (now_dt + timedelta(seconds=ttl_seconds)).strftime(_ISO)[:-3] + "Z"
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if current.status != RunStatus.AWAITING_START_APPROVAL:
                    raise MaxControlError("only an awaiting run can be approved")
                if charter_hash_value != current.charter_hash:
                    raise MaxControlError("charter hash does not match the stored Charter")
                charter = self._charter(row)
                approval_id = make_event_id("start_approval", current.project_id, {"run_id": run_id, "charter_hash": current.charter_hash, "approved_by": actor.actor_id, "approved_at": now, "nonce": uuid.uuid4().hex})
                approval = StartApproval(run_id=run_id, project_id=current.project_id, charter_hash=current.charter_hash, model_identity=current.model_identity, budget=current.budget, source_policy_hash=current.source_policy_hash, approval_id=approval_id, decision="approved", approved_by=actor.actor_id, approved_at=now, decision_authority="human", expires_at=expires)
                validate_start_approval(approval, expected_run_id=run_id, expected_project_id=current.project_id, expected_charter_hash=current.charter_hash, expected_model_identity=current.model_identity, expected_budget=current.budget, expected_source_policy_hash=current.source_policy_hash, now=now_dt).raise_if_invalid()
                existing = tuple(ApprovalConsumption.from_mapping(_loads(item["consumption_json"])) for item in connection.execute("SELECT consumption_json FROM max_approval_consumptions WHERE run_id=?", (run_id,)))
                transition = transition_run_state(current, RunStatus.APPROVED, approval=approval, now=now_dt, consumption_ledger=existing)
                if transition.approval_consumption is None:
                    raise MaxControlError("approval consumption was not produced")
                connection.execute(
                    "INSERT INTO max_start_approvals(approval_id, run_id, project_id, charter_hash, model_identity, budget_json, budget_hash, source_policy_hash, reason, approval_json, approval_hash, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (approval.approval_id, run_id, current.project_id, approval.charter_hash, approval.model_identity, _json(approval.budget), _hash(approval.budget), approval.source_policy_hash, reason.strip(), _json(approval), _hash(approval), now, actor.actor_id, actor.session_id),
                )
                consumption = transition.approval_consumption
                connection.execute(
                    "INSERT INTO max_approval_consumptions(consumption_id, approval_id, run_id, project_id, charter_hash, prior_state_version, resulting_state_version, consumed_at, consumption_json, consumption_hash, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (consumption.consumption_id, consumption.approval_id, run_id, consumption.project_id, consumption.charter_hash, consumption.prior_state_version, consumption.resulting_state_version, consumption.consumed_at, _json(consumption), _hash(consumption), actor.actor_id, actor.session_id),
                )
                self._update_run(connection, transition.new_state, now=now)
                transition_record = self._record_transition_result(connection, prior=current, transition=transition, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="approval_created", payload={"approval_id": approval.approval_id, "charter_hash": approval.charter_hash, "reason_hash": _hash(reason.strip()), "authority": "human"}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="approval_consumed", payload={"approval_id": approval.approval_id, "consumption_id": consumption.consumption_id, "prior_state_version": consumption.prior_state_version, "resulting_state_version": consumption.resulting_state_version}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="run_transition", payload={"from": current.status.value, "to": transition.new_state.status.value, "state_version": transition.new_state.state_version}, actor=actor, now=now)
            return {"approval": model_to_dict(approval), "consumption": model_to_dict(consumption), "transition_result": transition_record, "run": self._run_summary_from_state(transition.new_state, charter=charter)}
        except Exception as exc:
            if isinstance(exc, MaxControlError):
                raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def _acquire_lease_connection(self, connection: sqlite3.Connection, *, run_id: str, actor: Actor, ttl_seconds: int, now: str, allowed_statuses: set[RunStatus] | None = None) -> dict[str, Any]:
        if ttl_seconds < 1 or ttl_seconds > 86_400:
            raise MaxControlError("lease TTL is outside the supported range")
        row = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise MaxControlError("run lease row is missing")
        run_row = self._run_row(connection, run_id)
        status = RunStatus(run_row["status"])
        if status not in (allowed_statuses or {RunStatus.RUNNING}):
            raise MaxControlError("lease acquisition is not allowed in the current Run state")
        expiry = _parse_timestamp(row["expires_at"])
        # A release is an authoritative lifecycle transition.  Do not let a
        # clock-skewed future expires_at on the reused lease row make a
        # formally released lease look owned to a different process.
        if row["owner_id"] and not row["released_at"] and expiry is not None and expiry > _utc_now(self.clock) and (row["owner_id"] != actor.actor_id or row["session_id"] != actor.session_id):
            raise MaxControlError("run lease is held by another owner")
        token = int(row["fencing_token"]) + 1
        expires = (_utc_now(self.clock) + timedelta(seconds=ttl_seconds)).strftime(_ISO)[:-3] + "Z"
        connection.execute("UPDATE max_leases SET owner_id=?, session_id=?, fencing_token=?, expires_at=?, acquired_at=COALESCE(acquired_at, ?), renewed_at=?, released_at=NULL WHERE run_id=?", (actor.actor_id, actor.session_id, token, expires, now, now, run_id))
        return {"run_id": run_id, "owner_id": actor.actor_id, "session_id": actor.session_id, "fencing_token": token, "expires_at": expires, "acquired_at": row["acquired_at"] or now}

    def acquire_lease(self, *, run_id: str, actor: Actor, ttl_seconds: int = 60) -> dict[str, Any]:
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                current = self._run_state(self._run_row(connection, run_id))
                if current.status != RunStatus.RUNNING:
                    raise MaxControlError("only RUNNING Runs can acquire or take over a lease")
                lease = self._acquire_lease_connection(connection, run_id=run_id, actor=actor, ttl_seconds=ttl_seconds, now=now)
                self._append_event(connection, run_id=run_id, event_type="lease_acquired", payload={"owner_id": actor.actor_id, "session_id": actor.session_id, "fencing_token": lease["fencing_token"], "expires_at": lease["expires_at"]}, actor=actor, now=now)
            return lease
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def renew_lease(self, *, run_id: str, actor: Actor, fencing_token: int, ttl_seconds: int = 60) -> dict[str, Any]:
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                state = self._run_state(self._run_row(connection, run_id))
                if state.status != RunStatus.RUNNING:
                    raise MaxControlError("only RUNNING Runs can renew a lease")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                expires = (_utc_now(self.clock) + timedelta(seconds=ttl_seconds)).strftime(_ISO)[:-3] + "Z"
                connection.execute("UPDATE max_leases SET expires_at=?, renewed_at=? WHERE run_id=?", (expires, now, run_id))
                lease = {"run_id": run_id, "owner_id": actor.actor_id, "session_id": actor.session_id, "fencing_token": int(fencing_token), "expires_at": expires}
                self._append_event(connection, run_id=run_id, event_type="lease_renewed", payload={"fencing_token": int(fencing_token), "expires_at": expires}, actor=actor, now=now)
            return lease
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def release_lease(self, *, run_id: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                state = self._run_state(self._run_row(connection, run_id))
                if state.status != RunStatus.RUNNING:
                    raise MaxControlError("only RUNNING Runs can release a lease")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                connection.execute("UPDATE max_leases SET expires_at=?, released_at=? WHERE run_id=?", (now, now, run_id))
                self._append_event(connection, run_id=run_id, event_type="lease_released", payload={"fencing_token": int(fencing_token)}, actor=actor, now=now)
            return {"run_id": run_id, "released": True, "fencing_token": int(fencing_token)}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def _transition(self, *, run_id: str, target: RunStatus | str, actor: Actor, fencing_token: int | None = None, lease_ttl: int = 60) -> dict[str, Any]:
        now_dt = _utc_now(self.clock); now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                target_value = getattr(target, "value", target)
                if target_value in {RunStatus.PAUSED.value, RunStatus.CANCELLED.value} and current.status == RunStatus.RUNNING:
                    self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                if target_value == RunStatus.CANCELLED.value and current.status == RunStatus.PAUSED and not actor.is_admin:
                    raise MaxControlError("cancelling a paused Run requires human admin authority")
                if target_value == RunStatus.RUNNING.value and current.status == RunStatus.APPROVED:
                    lease = self._acquire_lease_connection(connection, run_id=run_id, actor=actor, ttl_seconds=lease_ttl, now=now, allowed_statuses={RunStatus.APPROVED})
                    transition = transition_run_state(current, RunStatus.RUNNING)
                else:
                    transition = transition_run_state(current, target)
                    lease = None
                if target_value == RunStatus.PAUSED.value:
                    if current.current_state_hash is None:
                        raise MaxControlError("pause requires a current Research State")
                    self._append_event(connection, run_id=run_id, event_type="pause_snapshot", payload={"state_hash": current.current_state_hash, "checkpoint_id": current.current_checkpoint_id, "budget_hash": _hash(current.budget)}, actor=actor, now=now)
                    connection.execute("UPDATE max_leases SET expires_at=?, released_at=? WHERE run_id=?", (now, now, run_id))
                    self._append_event(connection, run_id=run_id, event_type="lease_released", payload={"reason": "run_paused", "fencing_token": fencing_token}, actor=actor, now=now)
                self._update_run(connection, transition.new_state, now=now)
                transition_record = self._record_transition_result(connection, prior=current, transition=transition, actor=actor, now=now)
                if lease is not None:
                    self._append_event(connection, run_id=run_id, event_type="lease_acquired", payload={"owner_id": actor.actor_id, "session_id": actor.session_id, "fencing_token": lease["fencing_token"], "expires_at": lease["expires_at"]}, actor=actor, now=now)
                if target_value == RunStatus.CANCELLED.value and current.status == RunStatus.RUNNING:
                    connection.execute("UPDATE max_leases SET expires_at=?, released_at=? WHERE run_id=?", (now, now, run_id))
                    self._append_event(connection, run_id=run_id, event_type="lease_released", payload={"reason": "run_cancelled", "fencing_token": fencing_token}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="run_transition", payload={"from": current.status.value, "to": transition.new_state.status.value, "state_version": transition.new_state.state_version, "state_hash": transition.new_state.current_state_hash}, actor=actor, now=now)
            result = {"run": self._run_summary_from_state(transition.new_state), "transition": {"from": current.status.value, "to": transition.new_state.status.value, "state_version": transition.new_state.state_version}, "transition_result": transition_record}
            if lease is not None: result["lease"] = lease
            return result
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def start(self, *, run_id: str, actor: Actor, lease_ttl: int = 60) -> dict[str, Any]:
        return self._transition(run_id=run_id, target=RunStatus.RUNNING, actor=actor, lease_ttl=lease_ttl)

    def pause(self, *, run_id: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        return self._transition(run_id=run_id, target=RunStatus.PAUSED, actor=actor, fencing_token=fencing_token)

    def resume(self, *, run_id: str, actor: Actor, fencing_token: int | None = None, lease_ttl: int = 60, expected_state_version: int | None = None, expected_checkpoint_id: str | None = None, expected_state_hash: str | None = None) -> dict[str, Any]:
        if not actor.is_admin:
            raise MaxControlError("resume requires explicit human admin authority")
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if current.status != RunStatus.PAUSED:
                    raise MaxControlError("only PAUSED Runs can resume")
                if expected_state_version is not None and current.state_version != expected_state_version:
                    raise MaxControlError("resume state version expectation is stale")
                if expected_checkpoint_id is not None and current.current_checkpoint_id != expected_checkpoint_id:
                    raise MaxControlError("resume checkpoint expectation is stale")
                if expected_state_hash is not None and current.current_state_hash != expected_state_hash:
                    raise MaxControlError("resume state hash expectation is stale")
                # A portability handoff produces a durable recovery packet.
                # Resuming before an explicit server-owned acknowledgement
                # would make the new backend operate on an unacknowledged
                # state boundary, so fail closed.  Legacy runs without a
                # packet retain their existing resume semantics.
                packet_table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='max_rehydration_packets'"
                ).fetchone()
                if packet_table is not None:
                    packet = connection.execute(
                        "SELECT p.packet_id FROM max_rehydration_packets p "
                        "WHERE p.run_id=? ORDER BY p.created_at DESC, p.packet_id DESC LIMIT 1",
                        (run_id,),
                    ).fetchone()
                    if packet is not None:
                        ack = connection.execute(
                            "SELECT 1 FROM max_rehydration_packet_acks WHERE packet_id=?", (packet["packet_id"],)
                        ).fetchone()
                        target_ack_table = connection.execute(
                            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='max_rehydration_packet_target_acks'"
                        ).fetchone()
                        target_ack = None if target_ack_table is None else connection.execute(
                            "SELECT * FROM max_rehydration_packet_target_acks WHERE packet_id=? AND read_complete=1",
                            (packet["packet_id"],),
                        ).fetchone()
                        if ack is None or (target_ack_table is not None and target_ack is None):
                            raise MaxControlError("resume requires an acknowledged rehydration packet")
                        if target_ack_table is not None:
                            current_binding = connection.execute(
                                "SELECT binding_id,project_id FROM max_run_execution_binding_current WHERE run_id=?",
                                (run_id,),
                            ).fetchone()
                            current_handoff = connection.execute(
                                "SELECT handoff_approval_id,state,binding_id FROM max_backend_handoff_current WHERE run_id=?",
                                (run_id,),
                            ).fetchone()
                            if (
                                current_binding is None
                                or current_binding["binding_id"] != target_ack["new_binding_id"]
                                or current_binding["project_id"] != target_ack["project_id"]
                                or current_handoff is None
                                or current_handoff["handoff_approval_id"] != target_ack["handoff_approval_id"]
                                or current_handoff["state"] != "CONSUMED"
                                or current_handoff["binding_id"] != target_ack["new_binding_id"]
                            ):
                                raise MaxControlError("resume rehydration acknowledgement is not the current handoff/binding")
                lease = self._acquire_lease_connection(connection, run_id=run_id, actor=actor, ttl_seconds=lease_ttl, now=now, allowed_statuses={RunStatus.PAUSED})
                transition = transition_run_state(current, RunStatus.RUNNING)
                self._update_run(connection, transition.new_state, now=now)
                transition_record = self._record_transition_result(connection, prior=current, transition=transition, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="lease_acquired", payload={"owner_id": actor.actor_id, "session_id": actor.session_id, "fencing_token": lease["fencing_token"], "expires_at": lease["expires_at"], "reason": "resume"}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="run_transition", payload={"from": current.status.value, "to": transition.new_state.status.value, "state_version": transition.new_state.state_version}, actor=actor, now=now)
            return {"run": self._run_summary_from_state(transition.new_state), "lease": lease, "transition_result": transition_record}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def cancel(self, *, run_id: str, actor: Actor, fencing_token: int | None = None) -> dict[str, Any]:
        return self._transition(run_id=run_id, target=RunStatus.CANCELLED, actor=actor, fencing_token=fencing_token)

    def _open_iteration(self, connection: sqlite3.Connection, *, run_id: str) -> sqlite3.Row:
        pointer = connection.execute("SELECT iteration_id FROM max_iteration_current WHERE run_id=?", (run_id,)).fetchone()
        if pointer is None:
            raise MaxControlError("the Run has no open iteration")
        row = connection.execute("SELECT * FROM max_iterations WHERE iteration_id=? AND run_id=?", (pointer["iteration_id"], run_id)).fetchone()
        if row is None or row["status"] != "started":
            raise MaxControlError("the current iteration pointer is invalid")
        outcome = connection.execute("SELECT 1 FROM max_iteration_outcomes WHERE iteration_id=?", (row["iteration_id"],)).fetchone()
        if outcome is not None:
            raise MaxControlError("the current iteration already has an outcome")
        return row

    def begin_iteration(
        self,
        *,
        run_id: str,
        round_type: str,
        actor: Actor,
        fencing_token: int,
        input_state_hash: str | None = None,
        iteration_id: str | None = None,
        requested_sequence: int | None = None,
    ) -> dict[str, Any]:
        now = _timestamp(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if current.status != RunStatus.RUNNING:
                    raise MaxControlError("begin_iteration requires a RUNNING Run")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                if connection.execute("SELECT 1 FROM max_iteration_current WHERE run_id=?", (run_id,)).fetchone() is not None:
                    raise MaxControlError("a Run may have only one open iteration")
                kind = _round_type(round_type)
                contract_kind = {"exploration": "socratic_exploration", "adjudication": "habermasian_adjudication", "attack": "adversarial_attack", "rehydration": "rehydration_review", "acquisition_review": "acquisition_request"}.get(kind, kind)
                state_hash = input_state_hash or current.current_state_hash
                if state_hash != current.current_state_hash:
                    raise MaxControlError("iteration input state hash is stale")
                prior = connection.execute("SELECT MAX(sequence_no) AS sequence_no FROM max_iterations WHERE run_id=?", (run_id,)).fetchone()["sequence_no"]
                sequence = int(prior or 0) + 1
                if requested_sequence is not None and requested_sequence != sequence:
                    raise MaxControlError("iteration sequence is not contiguous")
                item_id = iteration_id or make_event_id("iteration", current.project_id, {"run_id": run_id, "sequence": sequence, "kind": kind})
                iteration = Iteration(current.project_id, run_id, sequence, contract_kind, status="started", iteration_id=item_id)
                validate_iteration(iteration).raise_if_invalid()
                connection.execute(
                    "INSERT INTO max_iterations(iteration_id, run_id, project_id, sequence_no, round_type, status, input_state_hash, output_state_hash, iteration_json, claim_snapshots_json, evidence_snapshots_json, counterevidence_snapshots_json, strategy_ledger_json, record_refs_json, budget_delta_json, started_at, finished_at, fencing_token, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, 'started', ?, NULL, ?, '[]', '[]', '[]', ?, '[]', '{}', ?, NULL, ?, ?, ?)",
                    (item_id, run_id, current.project_id, sequence, kind, state_hash, _json(iteration), _json(CoverageLedger()), now, fencing_token, actor.actor_id, actor.session_id),
                )
                connection.execute("INSERT INTO max_iteration_current(run_id, iteration_id, set_at) VALUES (?, ?, ?)", (run_id, item_id, now))
                updated = replace(current, iteration_index=sequence, state_version=current.state_version + 1)
                validate_run_state(updated).raise_if_invalid(); self._update_run(connection, updated, now=now)
                self._record_transition_result(connection, prior=current, transition=RunTransitionResult(updated), actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="iteration_begun", payload={"iteration_id": item_id, "sequence_no": sequence, "round_type": kind, "input_state_hash": state_hash, "fencing_token": fencing_token}, actor=actor, now=now)
            return {"iteration_id": item_id, "sequence_no": sequence, "round_type": kind, "status": "started", "input_state_hash": state_hash, "state_version": updated.state_version}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def _budget_delta_for_iteration(self, connection: sqlite3.Connection, *, run_id: str, iteration_id: str) -> dict[str, int | float]:
        delta: dict[str, int | float] = {}
        for row in connection.execute("SELECT operation, amount_json FROM max_budget_ledger WHERE run_id=? AND iteration_id=? ORDER BY sequence_no", (run_id, iteration_id)):
            amount = normalize_budget_amount(_loads(row["amount_json"]), allow_empty=True)
            sign = -1 if row["operation"] in {"release", "refund"} else 1
            for unit, value in amount.items():
                delta[unit] = delta.get(unit, 0) + sign * value
        return {key: value for key, value in sorted(delta.items()) if value}

    def _validate_iteration_snapshots(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        claims: Sequence[ClaimSnapshot],
        evidence: Sequence[EvidenceSnapshot],
        counterevidence: Sequence[EvidenceSnapshot],
    ) -> None:
        for snapshot in (*claims, *evidence, *counterevidence):
            version_row = connection.execute("SELECT v.object_json FROM max_canonical_object_versions v JOIN max_run_object_memberships m ON m.version_id=v.version_id WHERE m.run_id=? AND v.version_id=?", (run_id, snapshot.version_id)).fetchone()
            if version_row is None:
                raise MaxControlError("iteration snapshot version is not a member of this Run")
            try:
                obj = CanonicalObject.from_mapping(_loads(version_row["object_json"]))
            except Exception as exc:
                raise MaxControlError("iteration snapshot canonical version is invalid") from exc
            if isinstance(snapshot, ClaimSnapshot):
                expected = make_claim_snapshot(obj)
                if expected.claim_id != snapshot.claim_id or expected.status != snapshot.status or expected.semantic_hash != snapshot.semantic_hash:
                    raise MaxControlError("claim snapshot does not bind the exact canonical version")
            else:
                expected = make_evidence_snapshot(obj)
                if expected.evidence_id != snapshot.evidence_id or expected.status != snapshot.status or expected.semantic_hash != snapshot.semantic_hash:
                    raise MaxControlError("evidence snapshot does not bind the exact canonical version")

    def finish_iteration(
        self,
        *,
        run_id: str,
        iteration_id: str,
        actor: Actor,
        fencing_token: int,
        status: str = "completed",
        output_state_hash: str | None = None,
        claim_snapshots: Sequence[ClaimSnapshot | Mapping[str, Any]] = (),
        evidence_snapshots: Sequence[EvidenceSnapshot | Mapping[str, Any]] = (),
        counterevidence_snapshots: Sequence[EvidenceSnapshot | Mapping[str, Any]] = (),
        strategy_ledger: CoverageLedger | Mapping[str, Any] = CoverageLedger(),
        record_refs: Sequence[str] = (),
        artifact_links: Sequence[Mapping[str, Any]] = (),
        budget_delta: Mapping[str, Any] | None = None,
        outcome_metadata: Mapping[str, Any] | None = None,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        if status not in {"completed", "aborted"}:
            raise MaxControlError("iteration outcome must be completed or aborted")
        try:
            claims = tuple(item if isinstance(item, ClaimSnapshot) else ClaimSnapshot.from_mapping(item) for item in claim_snapshots)
            evidence = tuple(item if isinstance(item, EvidenceSnapshot) else EvidenceSnapshot.from_mapping(item) for item in evidence_snapshots)
            counter = tuple(item if isinstance(item, EvidenceSnapshot) else EvidenceSnapshot.from_mapping(item) for item in counterevidence_snapshots)
            ledger = strategy_ledger if isinstance(strategy_ledger, CoverageLedger) else CoverageLedger.from_mapping(strategy_ledger)
            refs = tuple(record_refs)
            if any(not isinstance(item, str) or not is_stable_id(item) for item in refs):
                raise MaxControlError("iteration record references must be stable IDs")
            requested_delta = normalize_budget_amount(budget_delta or {}, allow_empty=True)
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        now = _timestamp(self.clock); connection = _connection or self._connect(read_only=False)
        try:
            with (control_transaction(connection) if _connection is None else nullcontext(connection)):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if current.status != RunStatus.RUNNING:
                    raise MaxControlError("finish_iteration requires a RUNNING Run")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                begin = self._open_iteration(connection, run_id=run_id)
                if begin["iteration_id"] != iteration_id:
                    raise MaxControlError("iteration is not the current open iteration")
                actual_delta = self._budget_delta_for_iteration(connection, run_id=run_id, iteration_id=iteration_id)
                if requested_delta != actual_delta:
                    raise MaxControlError("iteration budget delta is not reconstructed from the ledger")
                self._validate_iteration_snapshots(connection, run_id=run_id, claims=claims, evidence=evidence, counterevidence=counter)
                if status == "completed":
                    if output_state_hash is not None and output_state_hash != current.current_state_hash:
                        raise MaxControlError("completed iteration output must bind the authoritative current state")
                    final_output = current.current_state_hash
                else:
                    final_output = output_state_hash
                normalized_artifacts: list[dict[str, Any]] = []
                for item in artifact_links:
                    if not isinstance(item, Mapping):
                        raise MaxControlError("iteration artifact link must be an object")
                    unknown = set(str(key) for key in item) - {"artifact_type", "artifact_id", "artifact", "artifact_json", "artifact_hash"}
                    if unknown or not isinstance(item.get("artifact_type"), str) or not item.get("artifact_type"):
                        raise MaxControlError("iteration artifact link is invalid")
                    artifact = item.get("artifact", item.get("artifact_json"))
                    if not isinstance(artifact, Mapping):
                        raise MaxControlError("typed iteration artifact is required")
                    artifact_id = item.get("artifact_id") or _hash(artifact)[:48]
                    if not isinstance(artifact_id, str) or not artifact_id:
                        raise MaxControlError("iteration artifact ID is invalid")
                    _reject_untrusted_payload(artifact)
                    artifact_type = item["artifact_type"]
                    try:
                        if artifact_type not in {"search_strategy", "attack_record", "attack", "discussion_session", "adjudication", "rehydration_output", "acquisition_request", "speculative_idea", "validity_audit", "minority_report", "cold_review_packet", "cold_review_result", "final_report", "formal_completion_evidence"}:
                            raise MaxControlError("unknown typed iteration artifact")
                        if artifact_type in {"attack_record", "attack"}:
                            typed = AttackRecord.from_mapping(artifact)
                            if typed.project_id != current.project_id or typed.run_id != run_id or typed.iteration_id != iteration_id:
                                raise MaxControlError("AttackRecord is outside the current Run or iteration")
                        elif artifact_type in {"discussion_session", "adjudication"}:
                            typed = DiscussionSession.from_mapping(artifact)
                            if typed.project_id != current.project_id or typed.run_id != run_id or typed.state_hash != begin["input_state_hash"]:
                                raise MaxControlError("DiscussionSession is outside the current Run boundary")
                        elif artifact_type == "rehydration_output":
                            typed = RehydrationOutput.from_mapping(artifact)
                            if not typed.accepted or typed.state is None or typed.state.project_id != current.project_id or typed.state.run_id != run_id:
                                raise MaxControlError("RehydrationOutput is not an accepted server-owned state")
                        elif artifact_type == "search_strategy":
                            SearchStrategy.from_mapping(artifact)
                        elif artifact_type == "acquisition_request":
                            AcquisitionRequest.from_mapping(artifact)
                        elif artifact_type == "speculative_idea":
                            SpeculativeIdea.from_mapping(artifact)
                        elif artifact_type == "validity_audit":
                            ValidityAudit.from_mapping(artifact)
                        elif artifact_type == "minority_report":
                            MinorityReport.from_mapping(artifact)
                        elif artifact_type == "cold_review_packet":
                            ColdReviewPacket.from_mapping(artifact)
                        elif artifact_type == "cold_review_result":
                            ColdReviewResult.from_mapping(artifact)
                        elif artifact_type == "final_report":
                            ReportProjection.from_mapping(artifact)
                        elif artifact_type == "formal_completion_evidence":
                            FormalCompletionEvidence.from_mapping(artifact)
                    except MaxControlError:
                        raise
                    except Exception as exc:
                        raise MaxControlError("typed cognitive artifact validation failed") from exc
                    artifact_hash = _hash(artifact)
                    normalized_artifacts.append({"artifact_type": item["artifact_type"], "artifact_id": artifact_id, "artifact": dict(artifact), "artifact_hash": artifact_hash})
                    link_id = make_event_id("iteration_artifact", current.project_id, {"iteration_id": iteration_id, "artifact_type": item["artifact_type"], "artifact_id": artifact_id})
                    connection.execute("INSERT INTO max_iteration_artifact_links(link_id, iteration_id, run_id, artifact_type, artifact_id, artifact_json, artifact_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (link_id, iteration_id, run_id, item["artifact_type"], artifact_id, _json(artifact), artifact_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                    group_row = connection.execute("SELECT group_id FROM max_runner_call_groups WHERE run_id=? AND iteration_id=? ORDER BY created_at DESC LIMIT 1", (run_id, iteration_id)).fetchone()
                    cognitive_id = make_event_id("cognitive_artifact", current.project_id, {"run_id": run_id, "iteration_id": iteration_id, "artifact_type": item["artifact_type"], "artifact_id": artifact_id})
                    connection.execute("INSERT INTO max_runner_cognitive_artifacts(artifact_id, run_id, project_id, iteration_id, group_id, artifact_type, phase, role, artifact_json, artifact_hash, accepted, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)", (cognitive_id, run_id, current.project_id, iteration_id, group_row["group_id"] if group_row else None, item["artifact_type"], begin["round_type"], None, _json(artifact), artifact_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                for budget_row in connection.execute("SELECT entry_id, amount_json FROM max_budget_ledger WHERE run_id=? AND iteration_id=? ORDER BY sequence_no", (run_id, iteration_id)):
                    link_id = make_event_id("iteration_budget", current.project_id, {"iteration_id": iteration_id, "entry_id": budget_row["entry_id"]})
                    amount_json = budget_row["amount_json"]
                    connection.execute("INSERT INTO max_iteration_budget_links(link_id, iteration_id, run_id, entry_id, amount_json, amount_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (link_id, iteration_id, run_id, budget_row["entry_id"], amount_json, _hash(_loads(amount_json)), now, actor.actor_id, actor.actor_kind, actor.session_id))
                artifact_summary = [{key: item[key] for key in ("artifact_type", "artifact_id", "artifact_hash")} for item in normalized_artifacts]
                metadata = dict(outcome_metadata or {})
                if metadata:
                    _reject_untrusted_payload(metadata)
                outcome = {"iteration_id": iteration_id, "run_id": run_id, "status": status, "input_state_hash": begin["input_state_hash"], "output_state_hash": final_output, "claim_snapshots": [model_to_dict(item) for item in claims], "evidence_snapshots": [model_to_dict(item) for item in evidence], "counterevidence_snapshots": [model_to_dict(item) for item in counter], "strategy_ledger": model_to_dict(ledger), "record_refs": list(refs), "budget_delta": actual_delta, "artifacts": artifact_summary, **metadata}
                outcome_id = make_event_id("iteration_outcome", current.project_id, {"iteration_id": iteration_id, "status": status, "output_state_hash": final_output})
                connection.execute("INSERT INTO max_iteration_outcomes(outcome_id, iteration_id, run_id, project_id, status, input_state_hash, output_state_hash, outcome_json, outcome_hash, claim_snapshots_json, evidence_snapshots_json, counterevidence_snapshots_json, strategy_ledger_json, record_refs_json, budget_delta_json, artifact_summary_json, started_at, finished_at, fencing_token, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (outcome_id, iteration_id, run_id, current.project_id, status, begin["input_state_hash"], final_output, _json(outcome), _hash(outcome), _json(claims), _json(evidence), _json(counter), _json(ledger), _json(refs), _json(actual_delta), _json(artifact_summary), begin["started_at"], now, fencing_token, actor.actor_id, actor.actor_kind, actor.session_id))
                # ``max_iterations`` is the immutable begin record.  The
                # append-only outcome row below is the authoritative finish
                # projection; updating the begin row would violate the
                # existing core trigger and erase the crash-safe lineage.
                connection.execute("DELETE FROM max_iteration_current WHERE run_id=?", (run_id,))
                updated = replace(current, state_version=current.state_version + 1)
                validate_run_state(updated).raise_if_invalid(); self._update_run(connection, updated, now=now)
                self._record_transition_result(connection, prior=current, transition=RunTransitionResult(updated), actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="iteration_finished", payload={"iteration_id": iteration_id, "outcome_id": outcome_id, "status": status, "input_state_hash": begin["input_state_hash"], "output_state_hash": final_output, "artifact_count": len(normalized_artifacts), "budget_delta_hash": _hash(actual_delta), "fencing_token": fencing_token}, actor=actor, now=now)
            return {"iteration_id": iteration_id, "outcome_id": outcome_id, "outcome_hash": _hash(outcome), "status": status, "input_state_hash": begin["input_state_hash"], "output_state_hash": final_output, "artifact_count": len(normalized_artifacts), "budget_delta": actual_delta}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            if _connection is None:
                connection.close()

    def _checkpoint_for_state_change(
        self,
        connection: sqlite3.Connection,
        *,
        current: MaxRunState,
        state: ResearchState,
        actor: Actor,
        fencing_token: int,
        now: str,
    ) -> str:
        pointer = connection.execute("SELECT checkpoint_id FROM max_checkpoint_current WHERE run_id=?", (current.run_id,)).fetchone()
        if pointer is None:
            raise MaxControlError("state change requires a current checkpoint")
        prior_row = connection.execute("SELECT * FROM max_checkpoints WHERE checkpoint_id=?", (pointer["checkpoint_id"],)).fetchone()
        if prior_row is None:
            raise MaxControlError("state change current checkpoint is missing")
        prior = Checkpoint.from_mapping(_loads(prior_row["checkpoint_json"]))
        latest_ids = tuple(sorted(state.latest_by_id))
        claim_ids = tuple(sorted(item.stable_id for item in state.latest_by_id.values() if str(getattr(item.kind, "value", item.kind)) == CanonicalObjectKind.CLAIM.value))
        evidence_ids = tuple(sorted(item.stable_id for item in state.latest_by_id.values() if str(getattr(item.kind, "value", item.kind)) == CanonicalObjectKind.EVIDENCE.value))
        working = replace(prior.working_state, iteration_index=current.iteration_index, budget_remaining=current.budget, canonical_object_ids=latest_ids, claim_ids=claim_ids, evidence_ids=evidence_ids)
        successor = replace(prior, checkpoint_id=make_event_id("checkpoint", current.project_id, {"run_id": current.run_id, "supersedes": prior.checkpoint_id, "state_hash": state.state_hash, "nonce": uuid.uuid4().hex}), supersedes_item_id=prior.checkpoint_id, working_state=working, budget=current.budget, iteration_pointer=current.iteration_index, canonical_ids=latest_ids, created_at=now, checkpoint_version=1)
        validate_checkpoint(successor, project_id=current.project_id, run_id=current.run_id, canonical_objects=state.objects).raise_if_invalid()
        lineage = int(prior_row["lineage_version"]) + 1
        connection.execute("INSERT INTO max_checkpoints(checkpoint_id, run_id, project_id, checkpoint_version, lineage_version, supersedes_item_id, state_hash, checkpoint_json, fencing_token, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (successor.checkpoint_id, current.run_id, current.project_id, successor.checkpoint_version, lineage, successor.supersedes_item_id, state.state_hash, _json(successor), fencing_token, now, actor.actor_id, actor.session_id))
        connection.execute("INSERT INTO max_checkpoint_current(run_id, checkpoint_id, set_at) VALUES (?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET checkpoint_id=excluded.checkpoint_id, set_at=excluded.set_at", (current.run_id, successor.checkpoint_id, now))
        self._append_event(connection, run_id=current.run_id, event_type="checkpoint_created", payload={"checkpoint_id": successor.checkpoint_id, "supersedes_item_id": successor.supersedes_item_id, "state_hash": state.state_hash, "reason": "canonical_state_change", "fencing_token": fencing_token}, actor=actor, now=now)
        return successor.checkpoint_id

    def apply_change_set(
        self,
        *,
        run_id: str,
        change_set: CanonicalChangeSet | Mapping[str, Any],
        actor: Actor,
        fencing_token: int,
    ) -> dict[str, Any]:
        try:
            value = change_set if isinstance(change_set, CanonicalChangeSet) else CanonicalChangeSet.from_mapping(change_set)
        except Exception as exc:
            raise _safe_error(exc) from exc
        if value.run_id != run_id:
            raise MaxControlError("canonical change set Run binding is invalid")
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if current.status != RunStatus.RUNNING:
                    raise MaxControlError("canonical mutation requires a RUNNING Run")
                if value.project_id != current.project_id:
                    raise MaxControlError("canonical change set project boundary failed")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                begin = self._open_iteration(connection, run_id=run_id)
                if begin["iteration_id"] != value.iteration_id:
                    raise MaxControlError("canonical change set is not bound to the open iteration")
                if value.input_state_hash != current.current_state_hash or begin["input_state_hash"] != value.input_state_hash and connection.execute("SELECT COUNT(*) FROM max_canonical_change_sets WHERE run_id=? AND iteration_id=?", (run_id, value.iteration_id)).fetchone()[0] == 0:
                    raise MaxControlError("canonical change set input state hash is stale")
                existing_objects = list(self._object_rows(connection, current.project_id, run_id))
                existing_relations = list(self._relation_rows(connection, current.project_id, run_id))
                additions: list[CanonicalObject] = []
                adopted_objects: list[CanonicalObject] = []
                for object_id in value.adopt_object_version_ids:
                    item = connection.execute("SELECT object_json FROM max_canonical_object_versions WHERE version_id=? AND project_id=?", (object_id, current.project_id)).fetchone()
                    if item is None:
                        raise MaxControlError("adopted object version is missing or crosses project boundary")
                    adopted_objects.append(CanonicalObject.from_mapping(_loads(item["object_json"])))
                for item in value.objects:
                    if item.project_id != current.project_id:
                        raise MaxControlError("canonical object crosses project boundary")
                    if connection.execute("SELECT 1 FROM max_canonical_object_versions WHERE version_id=?", (item.version_id,)).fetchone() is not None:
                        raise MaxControlError("an existing version must be adopted explicitly")
                    additions.append(item)
                all_objects = existing_objects + [item for item in adopted_objects if item.version_id not in {x.version_id for x in existing_objects}] + additions
                adopted_relations: list[CanonicalRelation] = []
                for relation_id in value.adopt_relation_ids:
                    item = connection.execute("SELECT relation_json FROM max_canonical_relations WHERE relation_id=? AND project_id=?", (relation_id, current.project_id)).fetchone()
                    if item is None:
                        raise MaxControlError("adopted relation is missing or crosses project boundary")
                    adopted_relations.append(CanonicalRelation.from_mapping(_loads(item["relation_json"])))
                new_relations: list[CanonicalRelation] = []
                for item in value.relations:
                    if item.project_id != current.project_id:
                        raise MaxControlError("canonical relation crosses project boundary")
                    if connection.execute("SELECT 1 FROM max_canonical_relations WHERE relation_id=?", (item.relation_id,)).fetchone() is not None:
                        raise MaxControlError("an existing relation must be adopted explicitly")
                    new_relations.append(item)
                all_relations = existing_relations + [item for item in adopted_relations if item.relation_id not in {x.relation_id for x in existing_relations}] + new_relations
                try:
                    rebuilt = rebuild_research_state(tuple(all_objects), tuple(all_relations), project_id=current.project_id, run_id=run_id)
                except Exception as exc:
                    raise MaxControlError("canonical change set does not produce a valid complete graph") from exc
                if value.expected_output_state_hash is not None and value.expected_output_state_hash != rebuilt.state_hash:
                    raise MaxControlError("expected output state hash does not match the server rebuild")
                change_hash = value.canonical_hash()
                change_id = value.change_set_id or make_event_id("change_set", current.project_id, {"run_id": run_id, "iteration_id": value.iteration_id, "change_hash": change_hash, "nonce": uuid.uuid4().hex})
                stored_change = {**value.payload(), "change_set_id": change_id, "expected_output_state_hash": rebuilt.state_hash}
                connection.execute("INSERT INTO max_canonical_change_sets(change_set_id, run_id, project_id, iteration_id, input_state_hash, expected_output_state_hash, change_set_json, change_set_hash, fencing_token, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? ,?)", (change_id, run_id, current.project_id, value.iteration_id, value.input_state_hash, rebuilt.state_hash, _json(stored_change), _hash(stored_change), fencing_token, now, actor.actor_id, actor.actor_kind, actor.session_id))
                for item in sorted(additions, key=lambda item: (item.stable_id, item.version)):
                    self._insert_object(connection, item, actor=actor, now=now, run_id=run_id, change_set_id=change_id)
                    self._append_event(connection, run_id=run_id, event_type="canonical_version_appended", payload={"version_id": item.version_id, "stable_id": item.stable_id, "kind": str(getattr(item.kind, "value", item.kind)), "change_set_id": change_id}, actor=actor, now=now)
                    self._append_event(connection, run_id=run_id, event_type="canonical_membership_added", payload={"version_id": item.version_id, "membership_kind": "object", "change_set_id": change_id}, actor=actor, now=now)
                for item in adopted_objects:
                    if connection.execute("SELECT 1 FROM max_run_object_memberships WHERE run_id=? AND version_id=?", (run_id, item.version_id)).fetchone() is None:
                        self._add_object_membership(connection, run_id=run_id, obj=item, actor=actor, now=now, change_set_id=change_id)
                        self._append_event(connection, run_id=run_id, event_type="canonical_membership_added", payload={"version_id": item.version_id, "membership_kind": "object", "change_set_id": change_id, "adopted": True}, actor=actor, now=now)
                for item in sorted(new_relations, key=lambda item: item.relation_id):
                    self._insert_relation(connection, item, actor=actor, now=now, run_id=run_id, change_set_id=change_id)
                    self._append_event(connection, run_id=run_id, event_type="canonical_relation_appended", payload={"relation_id": item.relation_id, "source_version_id": item.source_version_id, "target_version_id": item.target_version_id, "relation": item.relation, "change_set_id": change_id}, actor=actor, now=now)
                    self._append_event(connection, run_id=run_id, event_type="canonical_membership_added", payload={"relation_id": item.relation_id, "membership_kind": "relation", "change_set_id": change_id}, actor=actor, now=now)
                for item in adopted_relations:
                    if connection.execute("SELECT 1 FROM max_run_relation_memberships WHERE run_id=? AND relation_id=?", (run_id, item.relation_id)).fetchone() is None:
                        self._add_relation_membership(connection, run_id=run_id, relation=item, actor=actor, now=now, change_set_id=change_id)
                        self._append_event(connection, run_id=run_id, event_type="canonical_membership_added", payload={"relation_id": item.relation_id, "membership_kind": "relation", "change_set_id": change_id, "adopted": True}, actor=actor, now=now)
                self._save_state(connection, rebuilt, actor=actor, now=now)
                checkpoint_id = self._checkpoint_for_state_change(connection, current=current, state=rebuilt, actor=actor, fencing_token=fencing_token, now=now)
                updated = replace(current, current_state_hash=rebuilt.state_hash, current_checkpoint_id=checkpoint_id, state_version=current.state_version + 1)
                validate_run_state(updated).raise_if_invalid(); self._update_run(connection, updated, now=now)
                self._record_transition_result(connection, prior=current, transition=RunTransitionResult(updated), actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="canonical_change_set_applied", payload={"change_set_id": change_id, "change_set_hash": _hash(stored_change), "input_state_hash": value.input_state_hash, "output_state_hash": rebuilt.state_hash, "object_count": len(additions) + len(adopted_objects), "relation_count": len(new_relations) + len(adopted_relations), "fencing_token": fencing_token}, actor=actor, now=now)
            return {"change_set_id": change_id, "change_set_hash": _hash(stored_change), "input_state_hash": value.input_state_hash, "output_state_hash": rebuilt.state_hash, "state_version": updated.state_version}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def append_canonical_object(
        self,
        *,
        project_id: str,
        value: CanonicalObject | Mapping[str, Any],
        actor: Actor,
        run_id: str | None = None,
        fencing_token: int | None = None,
        iteration_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            obj = value if isinstance(value, CanonicalObject) else CanonicalObject.from_mapping(value)
            if obj.project_id != project_id:
                raise MaxControlError("canonical object project boundary failed")
        except Exception as exc:
            if isinstance(exc, MaxControlError):
                raise
            raise _safe_error(exc) from exc
        if not run_id or not iteration_id or fencing_token is None:
            raise MaxControlError("canonical object writes require run_id, iteration_id, and a fencing token")
        result = self.apply_change_set(
            run_id=run_id,
            change_set=CanonicalChangeSet(project_id=project_id, run_id=run_id, iteration_id=iteration_id, input_state_hash=self.get_state(run_id=run_id)["state_hash"], objects=(obj,)),
            actor=actor,
            fencing_token=fencing_token,
        )
        return {**model_to_dict(obj), "change_set_id": result["change_set_id"], "output_state_hash": result["output_state_hash"]}

    def append_canonical_relation(
        self,
        *,
        project_id: str,
        value: CanonicalRelation | Mapping[str, Any],
        actor: Actor,
        run_id: str | None = None,
        fencing_token: int | None = None,
        iteration_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            relation = value if isinstance(value, CanonicalRelation) else CanonicalRelation.from_mapping(value)
            if relation.project_id != project_id:
                raise MaxControlError("canonical relation project boundary failed")
        except Exception as exc:
            if isinstance(exc, MaxControlError):
                raise
            raise _safe_error(exc) from exc
        if not run_id or not iteration_id or fencing_token is None:
            raise MaxControlError("canonical relation writes require run_id, iteration_id, and a fencing token")
        result = self.apply_change_set(
            run_id=run_id,
            change_set=CanonicalChangeSet(project_id=project_id, run_id=run_id, iteration_id=iteration_id, input_state_hash=self.get_state(run_id=run_id)["state_hash"], relations=(relation,)),
            actor=actor,
            fencing_token=fencing_token,
        )
        return {**model_to_dict(relation), "change_set_id": result["change_set_id"], "output_state_hash": result["output_state_hash"]}

    def get_state(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            row = self._run_row(connection, run_id)
            state_row = connection.execute("SELECT state_json FROM max_research_states WHERE run_id=?", (run_id,)).fetchone()
            if state_row is None:
                raise MaxControlError("Research State is not initialized")
            try:
                state = ResearchState.from_mapping(_loads(state_row[0]))
            except Exception as exc:
                raise _safe_error(exc) from exc
            return model_to_dict(state)
        finally:
            connection.close()

    def save_research_state(
        self,
        *,
        run_id: str,
        state: ResearchState | Mapping[str, Any],
        actor: Actor,
        fencing_token: int | None = None,
        iteration_id: str | None = None,
        rehydration_input_hash: str | None = None,
        rehydration_output_hash: str | None = None,
        drift: Sequence[str] = (),
    ) -> dict[str, Any]:
        try:
            value = state if isinstance(state, ResearchState) else ResearchState.from_mapping(state)
        except Exception as exc:
            raise _safe_error(exc) from exc
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); self._require_project_run(row, value.project_id); current = self._run_state(row)
                if current.status != RunStatus.RUNNING or not iteration_id:
                    raise MaxControlError("Research State writes require a RUNNING Run and iteration context")
                if self._open_iteration(connection, run_id=run_id)["iteration_id"] != iteration_id:
                    raise MaxControlError("Research State write is outside the open iteration")
                if value.run_id != run_id or value.state_hash != self._rebuild_state(connection, project_id=value.project_id, run_id=run_id).state_hash:
                    raise MaxControlError("Research State is not the deterministic canonical rebuild")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                self._save_state(connection, value, actor=actor, now=now, rehydration_input_hash=rehydration_input_hash, rehydration_output_hash=rehydration_output_hash, drift=drift)
                updated = replace(current, current_state_hash=value.state_hash, state_version=current.state_version + 1)
                validate_run_state(updated).raise_if_invalid(); self._update_run(connection, updated, now=now)
                self._record_transition_result(connection, prior=current, transition=RunTransitionResult(updated), actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="research_state_saved", payload={"state_hash": value.state_hash, "state_version": updated.state_version, "rehydration_input_hash": rehydration_input_hash, "rehydration_output_hash": rehydration_output_hash, "drift_count": len(tuple(drift))}, actor=actor, now=now)
            return {"run_id": run_id, "state_hash": value.state_hash, "state_version": updated.state_version}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def create_checkpoint(
        self,
        *,
        run_id: str,
        checkpoint: Checkpoint | Mapping[str, Any],
        actor: Actor,
        fencing_token: int,
    ) -> dict[str, Any]:
        try:
            value = checkpoint if isinstance(checkpoint, Checkpoint) else Checkpoint.from_mapping(checkpoint)
        except Exception as exc:
            raise _safe_error(exc) from exc
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if value.project_id != current.project_id or value.run_id != run_id:
                    raise MaxControlError("checkpoint is outside the run boundary")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                if current.current_state_hash is None:
                    raise MaxControlError("checkpoint requires a current Research State")
                objects = self._object_rows(connection, current.project_id, run_id)
                validate_checkpoint(value, project_id=current.project_id, run_id=run_id, canonical_objects=objects).raise_if_invalid()
                pointer = connection.execute("SELECT checkpoint_id FROM max_checkpoint_current WHERE run_id=?", (run_id,)).fetchone()
                previous_id = pointer["checkpoint_id"] if pointer else None
                previous_version = connection.execute("SELECT lineage_version FROM max_checkpoints WHERE checkpoint_id=?", (previous_id,)).fetchone() if previous_id else None
                expected_version = int(previous_version["lineage_version"]) + 1 if previous_version else 1
                if value.checkpoint_version != 1 or expected_version < 1 or value.supersedes_item_id != previous_id:
                    raise MaxControlError("checkpoint successor must supersede the current checkpoint exactly")
                connection.execute(
                    "INSERT INTO max_checkpoints(checkpoint_id, run_id, project_id, checkpoint_version, lineage_version, supersedes_item_id, state_hash, checkpoint_json, fencing_token, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (value.checkpoint_id, run_id, current.project_id, value.checkpoint_version, expected_version, value.supersedes_item_id, current.current_state_hash, _json(value), fencing_token, now, actor.actor_id, actor.session_id),
                )
                connection.execute("INSERT INTO max_checkpoint_current(run_id, checkpoint_id, set_at) VALUES (?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET checkpoint_id=excluded.checkpoint_id, set_at=excluded.set_at", (run_id, value.checkpoint_id, now))
                updated = replace(current, current_checkpoint_id=value.checkpoint_id, state_version=current.state_version + 1)
                validate_run_state(updated).raise_if_invalid(); self._update_run(connection, updated, now=now)
                self._record_transition_result(connection, prior=current, transition=RunTransitionResult(updated), actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="checkpoint_created", payload={"checkpoint_id": value.checkpoint_id, "checkpoint_version": value.checkpoint_version, "supersedes_item_id": value.supersedes_item_id, "state_hash": current.current_state_hash, "fencing_token": fencing_token}, actor=actor, now=now)
            return {"checkpoint_id": value.checkpoint_id, "checkpoint_version": value.checkpoint_version, "lineage_version": expected_version, "state_hash": current.current_state_hash, "current": True}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def get_current_checkpoint(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            row = self._run_row(connection, run_id)
            item = connection.execute("SELECT c.* FROM max_checkpoints c JOIN max_checkpoint_current p ON p.checkpoint_id=c.checkpoint_id WHERE p.run_id=?", (run_id,)).fetchone()
            if item is None:
                raise MaxControlError("current checkpoint is not available")
            return {"checkpoint": _loads(item["checkpoint_json"]), "state_hash": item["state_hash"], "checkpoint_version": item["checkpoint_version"], "lineage_version": item["lineage_version"], "current": True}
        finally:
            connection.close()

    def record_iteration(self, *, run_id: str, record: IterationRecordInput, actor: Actor, fencing_token: int) -> dict[str, Any]:
        try:
            value = record.normalized(); iteration = value.iteration
            if not isinstance(iteration, Iteration):
                raise MaxControlError("iteration record is invalid")
            validate_iteration(iteration).raise_if_invalid()
            round_type = _round_type(iteration.kind)
            if iteration.status not in _STATUSES:
                raise MaxControlError("iteration status is invalid")
        except Exception as exc:
            raise _safe_error(exc) from exc
        if iteration.run_id != run_id:
            raise MaxControlError("iteration is outside the Run boundary")
        sequence_connection = self._connect(read_only=True)
        try:
            prior = sequence_connection.execute("SELECT MAX(sequence_no) AS sequence_no FROM max_iterations WHERE run_id=?", (run_id,)).fetchone()["sequence_no"]
        finally:
            sequence_connection.close()
        if iteration.sequence != int(prior or 0) + 1:
            raise MaxControlError("iteration sequence is not contiguous")
        if iteration.status == "completed" and value.output_state_hash and value.output_state_hash != self.get_state(run_id=run_id)["state_hash"]:
            raise MaxControlError("record_iteration cannot invent an output state; apply a change set first")
        begun = self.begin_iteration(run_id=run_id, round_type=iteration.kind, actor=actor, fencing_token=fencing_token, input_state_hash=value.input_state_hash, iteration_id=iteration.iteration_id, requested_sequence=iteration.sequence)
        if iteration.status == "started":
            return begun
        finished = self.finish_iteration(
            run_id=run_id, iteration_id=begun["iteration_id"], actor=actor, fencing_token=fencing_token, status=iteration.status,
            output_state_hash=value.output_state_hash, claim_snapshots=value.claim_snapshots, evidence_snapshots=value.evidence_snapshots,
            counterevidence_snapshots=value.counterevidence_snapshots, strategy_ledger=value.strategy_ledger,
            record_refs=value.record_refs, budget_delta=value.budget_delta,
        )
        return {**begun, **finished, "status": iteration.status}

    def _budget_rows(self, connection: sqlite3.Connection, run_id: str) -> list[sqlite3.Row]:
        return list(connection.execute("SELECT * FROM max_budget_ledger WHERE run_id=? ORDER BY sequence_no", (run_id,)))

    def _budget_reconstruct_connection(self, connection: sqlite3.Connection, *, run_id: str) -> dict[str, Any]:
        row = self._run_row(connection, run_id)
        limits = normalize_budget_limits(_loads(row["budget_policy_json"]))
        used: dict[str, int | float] = {unit: 0 for unit in limits}
        reserved: dict[str, int | float] = {unit: 0 for unit in limits}
        entries: list[dict[str, Any]] = []

        def ensure_unit(unit: str) -> None:
            if unit not in limits:
                raise MaxControlError("budget ledger unit is not declared by the Charter")
            used.setdefault(unit, 0); reserved.setdefault(unit, 0)

        for item in self._budget_rows(connection, run_id):
            amount = normalize_budget_amount(_loads(item["amount_json"]), allow_empty=True)
            operation = item["operation"]
            provenance_for_hash = _loads(item["provenance_json"])
            if not isinstance(provenance_for_hash, Mapping):
                raise MaxControlError("stored budget provenance is invalid")
            if item["request_hash"]:
                expected_request_hash = _hash({"operation": operation, "amount": amount, "reservation_id": None if operation == "reserve" else item["reservation_id"], "provenance": provenance_for_hash, "run_id": run_id, "iteration_id": item["iteration_id"]})
                if item["request_hash"] != expected_request_hash and provenance_for_hash.get("legacy") is not True:
                    raise MaxControlError("stored budget request hash does not bind its ledger request")
            if operation == "reserve":
                for unit, value in amount.items():
                    ensure_unit(unit)
                    if used[unit] + reserved[unit] + value > limits[unit]:
                        raise MaxControlError("stored budget ledger exceeds the Charter limit")
                    reserved[unit] += value
            elif operation == "commit":
                for unit, value in amount.items():
                    ensure_unit(unit)
                    if reserved[unit] < value:
                        raise MaxControlError("stored budget commit exceeds its reservation")
                    reserved[unit] -= value; used[unit] += value
                    if used[unit] > limits[unit]:
                        raise MaxControlError("stored budget ledger exceeds the Charter limit")
            elif operation == "release":
                for unit, value in amount.items():
                    ensure_unit(unit)
                    if reserved[unit] < value:
                        raise MaxControlError("stored budget release exceeds its reservation")
                    reserved[unit] -= value
            elif operation == "usage":
                provenance = provenance_for_hash
                if not isinstance(provenance, Mapping):
                    raise MaxControlError("stored budget usage lacks authoritative provenance")
                receipt_hash = provenance.get("receipt_hash")
                if receipt_hash:
                    receipt_row = connection.execute("SELECT receipt_hash, run_id, iteration_id, model_identity, amount_json FROM max_usage_receipts WHERE receipt_hash=? AND run_id=?", (receipt_hash, run_id)).fetchone()
                    if receipt_row is None or receipt_row["iteration_id"] != item["iteration_id"] or normalize_budget_amount(_loads(receipt_row["amount_json"])) != amount:
                        raise MaxControlError("stored usage receipt is not bound to the ledger entry")
                elif not (provenance.get("legacy") is True and item["request_hash"]) and provenance.get("server_owned") is not True:
                    raise MaxControlError("stored budget usage lacks a typed authoritative receipt")
                for unit, value in amount.items():
                    ensure_unit(unit); used[unit] += value
                    if used[unit] + reserved[unit] > limits[unit]:
                        raise MaxControlError("stored budget usage exceeds the Charter limit")
            elif operation == "refund":
                for unit, value in amount.items():
                    ensure_unit(unit)
                    if used[unit] < value:
                        raise MaxControlError("stored budget refund makes a negative balance")
                    used[unit] -= value
            else:
                raise MaxControlError("stored budget ledger contains an unsupported operation")
            entries.append({"entry_id": item["entry_id"], "sequence_no": item["sequence_no"], "operation": operation, "idempotency_key": item["idempotency_key"], "amount": amount, "reservation_id": item["reservation_id"], "iteration_id": item["iteration_id"], "request_hash": item["request_hash"], "created_at": item["created_at"]})
        available = {unit: limits[unit] - used[unit] - reserved[unit] for unit in limits}
        if any(value < 0 for value in available.values()):
            raise MaxControlError("budget ledger has a negative available balance")
        return {"limits": limits, "used": used, "reserved": reserved, "available": available, "entries": entries}

    def reconstruct_budget(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            return self._budget_reconstruct_connection(connection, run_id=run_id)
        finally:
            connection.close()

    def _reservation_remaining(self, connection: sqlite3.Connection, *, run_id: str, reservation_id: str) -> dict[str, int | float]:
        reserve = connection.execute("SELECT amount_json FROM max_budget_ledger WHERE run_id=? AND entry_id=? AND operation='reserve'", (run_id, reservation_id)).fetchone()
        if reserve is None:
            raise MaxControlError("budget reservation was not found")
        remaining = normalize_budget_amount(_loads(reserve[0]), allow_empty=True)
        for row in connection.execute("SELECT operation, amount_json FROM max_budget_ledger WHERE run_id=? AND reservation_id=? ORDER BY sequence_no", (run_id, reservation_id)):
            amount = normalize_budget_amount(_loads(row["amount_json"]), allow_empty=True)
            if row["operation"] in {"commit", "release"}:
                for unit, value in amount.items():
                    remaining[unit] = remaining.get(unit, 0) - value
                    if remaining[unit] < 0:
                        raise MaxControlError("budget reservation history is invalid")
        return {unit: value for unit, value in remaining.items() if value}

    def _budget_write(
        self,
        *,
        run_id: str,
        operation: str,
        amount: Mapping[str, Any] | None,
        idempotency_key: str,
        actor: Actor,
        fencing_token: int,
        reservation_id: str | None = None,
        provenance: Mapping[str, Any] | None = None,
        iteration_id: str | None = None,
        receipt: UsageReceipt | Mapping[str, Any] | None = None,
        logical_call_id: str | None = None,
        intent_hash: str | None = None,
        request_hash: str | None = None,
        provider_call_id: str | None = None,
        inference_profile_hash: str | None = None,
        server_owned: bool = False,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        if operation not in {"reserve", "commit", "release", "usage", "refund"}:
            raise MaxControlError("unsupported budget operation")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip() or len(idempotency_key) > 200:
            raise MaxControlError("budget idempotency key is required")
        now = _timestamp(self.clock); connection = _connection or self._connect(read_only=False)
        try:
            with (control_transaction(connection) if _connection is None else nullcontext(connection)):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if current.status != RunStatus.RUNNING:
                    raise MaxControlError("budget writes require a RUNNING Run")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                if amount is None and operation in {"commit", "release"}:
                    amount_value = {}
                else:
                    amount_value = normalize_budget_amount(amount or {}, allow_empty=False)
                # Resolve an existing commit/release idempotency key before
                # reconstructing the reservation remainder.  A retry after a
                # prior commit must return the original immutable entry even
                # though that commit has legitimately reduced the remaining
                # reservation below the requested amount.
                if operation in {"commit", "release"}:
                    existing_operation = connection.execute(
                        "SELECT * FROM max_budget_ledger WHERE run_id=? AND idempotency_key=?",
                        (run_id, idempotency_key.strip()),
                    ).fetchone()
                    if existing_operation is not None:
                        if existing_operation["operation"] != operation or existing_operation["reservation_id"] != reservation_id:
                            raise MaxControlError("CONFLICT: budget idempotency key request differs")
                        if iteration_id is not None and existing_operation["iteration_id"] != iteration_id:
                            raise MaxControlError("CONFLICT: budget idempotency key iteration differs")
                        stored_amount = normalize_budget_amount(_loads(existing_operation["amount_json"]), allow_empty=True)
                        if amount is not None and amount_value != stored_amount:
                            raise MaxControlError("CONFLICT: budget idempotency key amount differs")
                        return {"entry_id": existing_operation["entry_id"], "sequence_no": existing_operation["sequence_no"], "operation": existing_operation["operation"], "amount": stored_amount, "idempotent_retry": True, "balance": self._budget_reconstruct_connection(connection, run_id=run_id)}
                if operation in {"commit", "release"}:
                    if not reservation_id:
                        raise MaxControlError("commit and release require a reservation ID")
                    remaining = self._reservation_remaining(connection, run_id=run_id, reservation_id=reservation_id)
                    if amount is None:
                        amount_value = remaining
                    for unit, value in amount_value.items():
                        if value > remaining.get(unit, 0):
                            raise MaxControlError("budget operation exceeds the reservation")
                if not iteration_id:
                    raise MaxControlError("budget writes require an explicit iteration_id")
                if self._open_iteration(connection, run_id=run_id)["iteration_id"] != iteration_id:
                    raise MaxControlError("budget write is outside the open iteration")
                # ``amount=None`` means "the remaining reservation".  Once
                # the first release/commit is stored, that remaining amount
                # is zero; the immutable original entry must therefore be
                # returned before recomputing a different request hash.
                if amount is None and operation in {"commit", "release"}:
                    existing_remaining = connection.execute("SELECT * FROM max_budget_ledger WHERE run_id=? AND idempotency_key=?", (run_id, idempotency_key.strip())).fetchone()
                    if existing_remaining is not None:
                        if existing_remaining["operation"] != operation or existing_remaining["reservation_id"] != reservation_id:
                            raise MaxControlError("CONFLICT: budget idempotency key request differs")
                        return {"entry_id": existing_remaining["entry_id"], "sequence_no": existing_remaining["sequence_no"], "operation": existing_remaining["operation"], "amount": _loads(existing_remaining["amount_json"]), "idempotent_retry": True, "balance": self._budget_reconstruct_connection(connection, run_id=run_id)}
                provenance_value: dict[str, Any] = {}
                receipt_value: UsageReceipt | None = None
                if operation == "usage":
                    if receipt is None and not server_owned:
                        raise MaxControlError("usage requires a registered UsageAuthority and typed UsageReceipt")
                    if receipt is None and server_owned:
                        if not isinstance(provenance, Mapping) or provenance.get("server_owned") is not True:
                            raise MaxControlError("only the server may append a receipt-free usage charge")
                        _reject_untrusted_payload(provenance)
                        provenance_value = dict(provenance)
                    try:
                        receipt_value = receipt if isinstance(receipt, UsageReceipt) else UsageReceipt.from_mapping(receipt) if receipt is not None else None
                    except Exception as exc:
                        raise MaxControlError("usage receipt is invalid") from exc
                    if receipt_value is not None:
                        if self.usage_authority is None:
                            raise MaxControlError("usage requires a registered UsageAuthority")
                        if receipt_value.run_id != run_id or receipt_value.iteration_id != iteration_id or receipt_value.model_identity != current.model_identity:
                            raise MaxControlError("usage receipt is outside the Run or model binding")
                        if normalize_budget_amount(receipt_value.amount) != amount_value:
                            raise MaxControlError("usage receipt amount does not match the ledger request")
                        if receipt_value.payload_hash != receipt_value.computed_payload_hash() or receipt_value.receipt_hash not in (None, receipt_value.computed_receipt_hash()):
                            raise MaxControlError("usage receipt hash is invalid")
                        expected_context = {"logical_call_id": logical_call_id, "intent_hash": intent_hash, "request_hash": request_hash, "provider_call_id": provider_call_id, "inference_profile_hash": inference_profile_hash}
                        if any(value is not None for value in expected_context.values()):
                            for key, expected in expected_context.items():
                                if expected is not None and getattr(receipt_value, key) != expected:
                                    raise MaxControlError("usage receipt call binding is invalid")
                            if not all(getattr(receipt_value, key, "") for key in expected_context):
                                raise MaxControlError("usage receipt call binding is incomplete")
                        try:
                            verification = self.usage_authority.verify_usage_receipt(
                                receipt_value,
                                run_id=run_id,
                                iteration_id=iteration_id,
                                model_identity=current.model_identity,
                                logical_call_id=logical_call_id,
                                intent_hash=intent_hash,
                                request_hash=request_hash,
                                provider_call_id=provider_call_id,
                                inference_profile_hash=inference_profile_hash,
                            )
                        except Exception as exc:
                            raise MaxControlError("usage receipt authority rejected the receipt") from exc
                        if verification is False or verification is None:
                            raise MaxControlError("usage receipt authority rejected the receipt")
                        provenance_value = {"receipt_hash": receipt_value.receipt_hash or receipt_value.computed_receipt_hash(), "authority_id": receipt_value.authority_id, "verification": dict(verification) if isinstance(verification, Mapping) else {"verified": True}}
                        _reject_untrusted_payload(provenance_value)
                elif provenance:
                    _reject_untrusted_payload(provenance)
                    provenance_value = dict(provenance)
                request_hash = _hash({"operation": operation, "amount": amount_value, "reservation_id": reservation_id, "provenance": provenance_value, "run_id": run_id, "iteration_id": iteration_id})
                existing = connection.execute("SELECT * FROM max_budget_ledger WHERE run_id=? AND idempotency_key=?", (run_id, idempotency_key.strip())).fetchone()
                if existing is not None:
                    if existing["request_hash"] != request_hash:
                        raise MaxControlError("CONFLICT: budget idempotency key request differs")
                    return {"entry_id": existing["entry_id"], "sequence_no": existing["sequence_no"], "operation": existing["operation"], "amount": _loads(existing["amount_json"]), "idempotent_retry": True, "balance": self._budget_reconstruct_connection(connection, run_id=run_id)}
                if receipt_value is not None:
                    connection.execute("INSERT INTO max_usage_receipts(receipt_id, run_id, iteration_id, model_identity, amount_json, issued_at, authority_id, payload_hash, receipt_json, receipt_hash, verifier_json, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (receipt_value.receipt_id, run_id, iteration_id, receipt_value.model_identity, _json(amount_value), receipt_value.issued_at, receipt_value.authority_id, receipt_value.payload_hash, _json(receipt_value.as_mapping()), receipt_value.receipt_hash or receipt_value.computed_receipt_hash(), _json(provenance_value.get("verification", {})), now, actor.actor_id, actor.actor_kind, actor.session_id))
                sequence_row = connection.execute("SELECT MAX(sequence_no) AS sequence_no FROM max_budget_ledger WHERE run_id=?", (run_id,)).fetchone()
                sequence = int(sequence_row["sequence_no"] or 0) + 1
                entry_id = make_event_id("budget_entry", current.project_id, {"run_id": run_id, "sequence_no": sequence, "idempotency_key": idempotency_key.strip()})
                connection.execute(
                    "INSERT INTO max_budget_ledger(entry_id, run_id, sequence_no, operation, idempotency_key, amount_json, provenance_json, reservation_id, created_at, actor_id, actor_session, request_hash, iteration_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (entry_id, run_id, sequence, operation, idempotency_key.strip(), _json(amount_value), _json(provenance_value), entry_id if operation == "reserve" else reservation_id, now, actor.actor_id, actor.session_id, request_hash, iteration_id),
                )
                balance = self._budget_reconstruct_connection(connection, run_id=run_id)
                self._append_event(connection, run_id=run_id, event_type="budget_ledger_appended", payload={"entry_id": entry_id, "sequence_no": sequence, "operation": operation, "amount_hash": _hash(amount_value), "reservation_id": entry_id if operation == "reserve" else reservation_id, "fencing_token": fencing_token}, actor=actor, now=now)
            return {"entry_id": entry_id, "sequence_no": sequence, "operation": operation, "amount": amount_value, "reservation_id": entry_id if operation == "reserve" else reservation_id, "idempotent_retry": False, "request_hash": request_hash, "iteration_id": iteration_id, "balance": balance}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            if _connection is None:
                connection.close()

    def reserve_budget(self, *, run_id: str, amount: Mapping[str, Any], idempotency_key: str, actor: Actor, fencing_token: int, iteration_id: str | None = None) -> dict[str, Any]:
        return self._budget_write(run_id=run_id, operation="reserve", amount=amount, idempotency_key=idempotency_key, actor=actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def commit_budget(self, *, run_id: str, reservation_id: str, amount: Mapping[str, Any] | None, idempotency_key: str, actor: Actor, fencing_token: int, iteration_id: str | None = None) -> dict[str, Any]:
        return self._budget_write(run_id=run_id, operation="commit", amount=amount, reservation_id=reservation_id, idempotency_key=idempotency_key, actor=actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def release_budget(self, *, run_id: str, reservation_id: str, amount: Mapping[str, Any] | None, idempotency_key: str, actor: Actor, fencing_token: int, iteration_id: str | None = None) -> dict[str, Any]:
        return self._budget_write(run_id=run_id, operation="release", amount=amount, reservation_id=reservation_id, idempotency_key=idempotency_key, actor=actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def record_authoritative_usage(
        self,
        *,
        run_id: str,
        amount: Mapping[str, Any],
        provenance: Mapping[str, Any] | None = None,
        receipt: UsageReceipt | Mapping[str, Any] | None = None,
        idempotency_key: str,
        actor: Actor,
        fencing_token: int,
        iteration_id: str | None = None,
        logical_call_id: str | None = None,
        intent_hash: str | None = None,
        request_hash: str | None = None,
        provider_call_id: str | None = None,
        inference_profile_hash: str | None = None,
    ) -> dict[str, Any]:
        return self._budget_write(run_id=run_id, operation="usage", amount=amount, provenance=provenance, receipt=receipt, idempotency_key=idempotency_key, actor=actor, fencing_token=fencing_token, iteration_id=iteration_id, logical_call_id=logical_call_id, intent_hash=intent_hash, request_hash=request_hash, provider_call_id=provider_call_id, inference_profile_hash=inference_profile_hash)

    def record_server_usage(
        self,
        *,
        run_id: str,
        amount: Mapping[str, Any],
        idempotency_key: str,
        actor: Actor,
        fencing_token: int,
        iteration_id: str,
        charge_kind: str,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        """Append a service-owned charge, such as one iteration count.

        This path deliberately has no client/provider receipt.  It is only
        reachable through the named repository method and is marked in the
        immutable provenance so public verification can distinguish it from a
        model-supplied usage claim.
        """

        if not isinstance(charge_kind, str) or not charge_kind.strip():
            raise MaxControlError("server usage charge kind is required")
        if charge_kind != "iteration" or normalize_budget_amount(amount) != {"iteration_count": 1}:
            raise MaxControlError("server usage is limited to one service-owned iteration unit")
        return self._budget_write(
            run_id=run_id,
            operation="usage",
            amount=amount,
            provenance={"server_owned": True, "charge_kind": charge_kind},
            receipt=None,
            idempotency_key=idempotency_key,
            actor=actor,
            fencing_token=fencing_token,
            iteration_id=iteration_id,
            server_owned=True,
            _connection=_connection,
        )

    def refund_budget(self, *, run_id: str, amount: Mapping[str, Any], idempotency_key: str, actor: Actor, fencing_token: int, iteration_id: str | None = None) -> dict[str, Any]:
        return self._budget_write(run_id=run_id, operation="refund", amount=amount, idempotency_key=idempotency_key, actor=actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def _history_for_completion(self, connection: sqlite3.Connection, *, run_id: str, current_state_hash: str) -> dict[str, Any]:
        rows = list(connection.execute("SELECT i.sequence_no, i.iteration_id, i.round_type, o.status, o.input_state_hash, o.output_state_hash, o.claim_snapshots_json, o.evidence_snapshots_json, o.counterevidence_snapshots_json, o.strategy_ledger_json, o.budget_delta_json, o.artifact_summary_json FROM max_iterations i JOIN max_iteration_outcomes o ON o.iteration_id=i.iteration_id WHERE i.run_id=? ORDER BY i.sequence_no", (run_id,)))
        all_rows = list(connection.execute("SELECT sequence_no FROM max_iterations WHERE run_id=? ORDER BY sequence_no", (run_id,)))
        sequences = [int(row["sequence_no"]) for row in all_rows]
        if sequences != list(range(1, len(sequences) + 1)):
            raise MaxControlError("iteration history is not contiguous")
        completed = [row for row in rows if row["status"] == "completed" and row["output_state_hash"]]
        if len(completed) < 2 or completed[-1]["output_state_hash"] != current_state_hash or completed[-2]["output_state_hash"] != current_state_hash:
            raise MaxControlError("completion history does not prove two consecutive stable outcome rounds")
        rounds = {row["round_type"] for row in completed}
        if not {"attack", "adjudication", "rehydration"}.issubset(rounds):
            raise MaxControlError("completion history lacks attack, adjudication, or rehydration rounds")
        artifacts: dict[str, list[Any]] = {}
        for row in completed:
            if not _loads(row["claim_snapshots_json"]) or not _loads(row["evidence_snapshots_json"]) or not _loads(row["counterevidence_snapshots_json"]):
                raise MaxControlError("completion history lacks persisted canonical snapshots")
            try:
                persisted_ledger = CoverageLedger.from_mapping(_loads(row["strategy_ledger_json"]))
            except Exception as exc:
                raise MaxControlError("completion history contains an invalid strategy ledger") from exc
            if not persisted_ledger.strategies or not persisted_ledger.required_families:
                raise MaxControlError("completion history lacks a persisted strategy ledger")
            links = list(connection.execute("SELECT artifact_type, artifact_id, artifact_json, artifact_hash FROM max_iteration_artifact_links WHERE run_id=? AND iteration_id=? ORDER BY artifact_type, artifact_id", (run_id, row["iteration_id"])))
            for link in links:
                try:
                    artifact = _loads(link["artifact_json"])
                    if _hash(artifact) != link["artifact_hash"]:
                        raise ValueError("artifact hash mismatch")
                except Exception as exc:
                    raise MaxControlError("persisted completion artifact is invalid") from exc
                artifacts.setdefault(link["artifact_type"], []).append(artifact)
            if row["round_type"] == "attack" and not any(key in artifacts for key in ("attack_record", "attack")):
                raise MaxControlError("attack round lacks a typed AttackRecord")
            if row["round_type"] == "adjudication" and not any(key in artifacts for key in ("discussion_session", "adjudication")):
                raise MaxControlError("adjudication round lacks a typed DiscussionSession")
            if row["round_type"] == "rehydration" and "rehydration_output" not in artifacts:
                raise MaxControlError("rehydration round lacks a persisted RehydrationOutput")
        for required in ("cold_review_packet", "cold_review_result", "final_report", "formal_completion_evidence"):
            if required not in artifacts:
                raise MaxControlError("completion history lacks a persisted typed " + required)
        return {"iteration_count": len(all_rows), "completed_count": len(completed), "round_types": sorted(rounds), "stable_rounds": 2, "rows": rows, "artifacts": artifacts}

    def _assemble_completion_input(self, connection: sqlite3.Connection, *, run_id: str) -> tuple[CompletionEvaluationInput, dict[str, Any]]:
        row = self._run_row(connection, run_id); current = self._run_state(row); charter = self._charter(row)
        state_row = connection.execute("SELECT state_json FROM max_research_states WHERE run_id=?", (run_id,)).fetchone()
        if state_row is None:
            raise MaxControlError("completion requires a persisted Research State")
        state = ResearchState.from_mapping(_loads(state_row["state_json"]))
        if state.state_hash != current.current_state_hash:
            raise MaxControlError("completion Research State is stale")
        history = self._history_for_completion(connection, run_id=run_id, current_state_hash=current.current_state_hash or "")
        artifacts = history["artifacts"]
        def one(name: str, cls: Any) -> Any:
            values = artifacts.get(name) or artifacts.get(name.removesuffix("_record")) or []
            if not values:
                raise MaxControlError("completion artifact is missing: " + name)
            try:
                return cls.from_mapping(values[-1])
            except Exception as exc:
                raise MaxControlError("completion artifact is not the required typed object: " + name) from exc
        attacks = tuple(AttackRecord.from_mapping(item) for item in (artifacts.get("attack_record") or artifacts.get("attack") or []))
        discussions = tuple(DiscussionSession.from_mapping(item) for item in (artifacts.get("discussion_session") or artifacts.get("adjudication") or []))
        rehydration_output = one("rehydration_output", RehydrationOutput)
        packet = one("cold_review_packet", ColdReviewPacket)
        review = one("cold_review_result", ColdReviewResult)
        report = one("final_report", ReportProjection)
        formal = one("formal_completion_evidence", FormalCompletionEvidence)
        claim_snapshots: list[ClaimSnapshot] = []; evidence_snapshots: list[EvidenceSnapshot] = []; counter_snapshots: list[EvidenceSnapshot] = []
        ledger = CoverageLedger()
        for item in history["rows"]:
            if item["status"] != "completed":
                continue
            claim_snapshots.extend(ClaimSnapshot.from_mapping(value) for value in _loads(item["claim_snapshots_json"]))
            evidence_snapshots.extend(EvidenceSnapshot.from_mapping(value) for value in _loads(item["evidence_snapshots_json"]))
            counter_snapshots.extend(EvidenceSnapshot.from_mapping(value) for value in _loads(item["counterevidence_snapshots_json"]))
            candidate = CoverageLedger.from_mapping(_loads(item["strategy_ledger_json"]))
            if candidate.strategies or candidate.required_families:
                ledger = candidate
        budget = self._budget_reconstruct_connection(connection, run_id=run_id)
        evaluation = CompletionEvaluationInput(
            project_id=current.project_id, run_id=run_id, charter_hash=current.charter_hash, state_hash=current.current_state_hash or "",
            charter=charter, run_state=current, research_state=state, strategy_ledger=ledger, attack_records=attacks,
            discussion_sessions=discussions, rehydration_output=rehydration_output, cold_review_packet=packet,
            cold_review_result=review, final_report=report, formal_completion_evidence=formal,
            claim_snapshots=tuple(claim_snapshots), evidence_snapshots=tuple(evidence_snapshots), counterevidence_snapshots=tuple(counter_snapshots),
            budget_snapshot=charter.budget, source_policy_snapshot=charter.source_policy, model_identity=current.model_identity,
            # Bind the pure input to the last authoritative Run update so an
            # evaluate→persist round trip does not change its hash merely
            # because wall-clock time advanced between the two calls.
            evaluated_at=row["updated_at"], current_checkpoint_id=current.current_checkpoint_id,
        )
        return evaluation, {"history": history, "budget_reconstruction": budget}

    def evaluate_completion(self, *, run_id: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            current = self._run_state(self._run_row(connection, run_id))
            if current.status != RunStatus.RUNNING:
                raise MaxControlError("completion evaluation requires a RUNNING Run")
            self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=_timestamp(self.clock))
            evaluation, facts = self._assemble_completion_input(connection, run_id=run_id)
            result = evaluate_completion_result(evaluation)
            return {"evaluation_input": model_to_dict(evaluation), "input_hash": evaluation.input_hash, "result": model_to_dict(result), "passed": bool(result.gate_result.passed), "facts": {"history": {key: value for key, value in facts["history"].items() if key not in {"artifacts", "rows"}}, "budget": facts["budget_reconstruction"]}}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def persist_completion(
        self,
        *,
        run_id: str,
        evaluation_input: CompletionEvaluationInput | Mapping[str, Any] | None = None,
        result: CompletionResult | Mapping[str, Any] | None = None,
        expected_input_hash: str | None = None,
        actor: Actor,
        fencing_token: int,
    ) -> dict[str, Any]:
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if current.status != RunStatus.RUNNING:
                    raise MaxControlError("completion persistence requires a RUNNING run")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                input_value, facts = self._assemble_completion_input(connection, run_id=run_id)
                if expected_input_hash is not None and expected_input_hash != input_value.input_hash:
                    raise MaxControlError("completion input hash is stale")
                if evaluation_input is not None:
                    try: submitted_input = evaluation_input if isinstance(evaluation_input, CompletionEvaluationInput) else CompletionEvaluationInput.from_mapping(evaluation_input)
                    except Exception as exc: raise MaxControlError("submitted completion input is not a valid typed object") from exc
                    if model_to_dict(submitted_input) != model_to_dict(input_value):
                        raise MaxControlError("submitted completion input differs from the database assembly")
                expected = evaluate_completion_result(input_value)
                if result is not None:
                    try: result_value = result if isinstance(result, CompletionResult) else CompletionResult.from_mapping(result)
                    except Exception as exc: raise MaxControlError("submitted CompletionResult is not typed") from exc
                    if model_to_dict(result_value) != model_to_dict(expected):
                        raise MaxControlError("submitted CompletionResult differs from the recomputed result")
                validate_completion_result(expected, evaluation_input=input_value, current_run_state=current).raise_if_invalid()
                transition = transition_run_state(current, RunStatus.COMPLETED, completion_result=expected, completion_input=input_value)
                self._update_run(connection, transition.new_state, now=now, completion=expected)
                transition_record = self._record_transition_result(connection, prior=current, transition=transition, actor=actor, now=now)
                connection.execute("UPDATE max_leases SET expires_at=?, released_at=? WHERE run_id=?", (now, now, run_id))
                self._append_event(connection, run_id=run_id, event_type="lease_released", payload={"reason": "run_completed", "fencing_token": fencing_token}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="completion_persisted", payload={"result_id": expected.result_id, "state_hash": expected.state_hash, "input_hash": input_value.input_hash, "history_hash": _hash(facts["history"]), "fencing_token": fencing_token}, actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="run_transition", payload={"from": current.status.value, "to": transition.new_state.status.value, "state_version": transition.new_state.state_version}, actor=actor, now=now)
            return {"run": self._run_summary_from_state(transition.new_state), "completion_result_id": expected.result_id, "input_hash": input_value.input_hash, "history": {key: value for key, value in facts["history"].items() if key not in {"artifacts", "rows"}}, "transition_result": transition_record}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def rehydrate_run(self, *, run_id: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        now = _timestamp(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._run_row(connection, run_id); current = self._run_state(row)
                if current.status != RunStatus.RUNNING:
                    raise MaxControlError("rehydration requires a RUNNING Run")
                self._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                iteration = self._open_iteration(connection, run_id=run_id)
                pointer = connection.execute("SELECT checkpoint_id FROM max_checkpoint_current WHERE run_id=?", (run_id,)).fetchone()
                if pointer is None:
                    raise MaxControlError("rehydration requires a current checkpoint")
                checkpoint_row = connection.execute("SELECT checkpoint_json FROM max_checkpoints WHERE checkpoint_id=?", (pointer["checkpoint_id"],)).fetchone()
                if checkpoint_row is None:
                    raise MaxControlError("current checkpoint is missing")
                checkpoint = Checkpoint.from_mapping(_loads(checkpoint_row[0]))
                objects = self._object_rows(connection, current.project_id, run_id)
                relations = self._relation_rows(connection, current.project_id, run_id)
                state_row = connection.execute("SELECT state_json FROM max_research_states WHERE run_id=?", (run_id,)).fetchone()
                prior = ResearchState.from_mapping(_loads(state_row[0])) if state_row else None
                request = RehydrationInput(project_id=current.project_id, run_id=run_id, checkpoint=checkpoint, canonical_objects=objects, relations=relations, working_summary=model_to_dict(checkpoint.working_state), prior_state=prior, iteration_index=checkpoint.iteration_pointer)
                output = rehydrate(request)
                input_hash = _hash(request); output_hash = _hash(output)
                if not output.accepted or output.state is None:
                    raise MaxControlError("rehydration detected canonical drift")
                self._save_state(connection, output.state, actor=actor, now=now, rehydration_input_hash=input_hash, rehydration_output_hash=output_hash, drift=tuple(str(item) for item in output.drift_flags))
                artifact_id = output_hash[:48]
                connection.execute("INSERT INTO max_iteration_artifact_links(link_id, iteration_id, run_id, artifact_type, artifact_id, artifact_json, artifact_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (make_event_id("iteration_artifact", current.project_id, {"iteration_id": iteration["iteration_id"], "artifact_type": "rehydration_output", "artifact_id": artifact_id}), iteration["iteration_id"], run_id, "rehydration_output", artifact_id, _json(output), _hash(output), now, actor.actor_id, actor.actor_kind, actor.session_id))
                connection.execute("INSERT INTO max_runner_cognitive_artifacts(artifact_id, run_id, project_id, iteration_id, group_id, artifact_type, phase, role, artifact_json, artifact_hash, accepted, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, (SELECT group_id FROM max_runner_call_groups WHERE run_id=? AND iteration_id=? ORDER BY created_at DESC LIMIT 1), 'rehydration_output', 'rehydration', 'server', ?, ?, 1, ?, ?, ?, ?)", (make_event_id("cognitive_artifact", current.project_id, {"run_id": run_id, "iteration_id": iteration["iteration_id"], "artifact_type": "rehydration_output", "artifact_id": artifact_id}), run_id, current.project_id, iteration["iteration_id"], run_id, iteration["iteration_id"], _json(output), _hash(output), now, actor.actor_id, actor.actor_kind, actor.session_id))
                updated = replace(current, current_state_hash=output.state.state_hash, state_version=current.state_version + 1)
                validate_run_state(updated).raise_if_invalid(); self._update_run(connection, updated, now=now)
                self._record_transition_result(connection, prior=current, transition=RunTransitionResult(updated), actor=actor, now=now)
                self._append_event(connection, run_id=run_id, event_type="rehydration_recorded", payload={"checkpoint_id": checkpoint.checkpoint_id, "iteration_id": iteration["iteration_id"], "input_hash": input_hash, "output_hash": output_hash, "state_hash": output.state.state_hash, "drift_count": len(output.drift_flags), "fencing_token": fencing_token}, actor=actor, now=now)
            return {"accepted": True, "checkpoint_id": checkpoint.checkpoint_id, "input_hash": input_hash, "output_hash": output_hash, "state_hash": output.state.state_hash, "drift_flags": list(output.drift_flags), "output": model_to_dict(output), "iteration_id": iteration["iteration_id"]}
        except Exception as exc:
            if isinstance(exc, MaxControlError): raise
            raise _safe_error(exc) from exc
        finally:
            connection.close()

    def list_events(self, *, run_id: str, cursor: int = 0, limit: int = 50) -> dict[str, Any]:
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise MaxControlError("event cursor must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 200:
            raise MaxControlError("event limit is outside the supported range")
        connection = self._connect(read_only=True)
        try:
            self._run_row(connection, run_id)
            rows = list(connection.execute("SELECT event_id, sequence_no, event_type, payload_hash, previous_event_hash, event_hash, actor_id, actor_kind, session_id, created_at FROM max_events WHERE run_id=? AND sequence_no>? ORDER BY sequence_no LIMIT ?", (run_id, cursor, limit)))
            items = [dict(row) for row in rows]
            next_cursor = items[-1]["sequence_no"] if len(items) == limit else None
            return {"run_id": run_id, "events": items, "cursor": cursor, "next_cursor": next_cursor}
        finally:
            connection.close()

    def _verify_event_chain(self, connection: sqlite3.Connection, *, run_id: str) -> dict[str, Any]:
        rows = list(connection.execute("SELECT * FROM max_events WHERE run_id=? ORDER BY sequence_no", (run_id,)))
        previous = ""; expected_sequence = 1; issues: list[str] = []
        for row in rows:
            if int(row["sequence_no"]) != expected_sequence:
                issues.append("event sequence is not contiguous")
            try:
                payload = _loads(row["payload_json"])
                if _hash(payload) != row["payload_hash"]:
                    issues.append("event payload hash mismatch")
                identity = {"run_id": run_id, "sequence_no": row["sequence_no"], "event_type": row["event_type"], "payload_hash": row["payload_hash"], "previous_event_hash": row["previous_event_hash"]}
                expected_hash = _hash({"event_id": row["event_id"], **identity, "payload_json": row["payload_json"], "actor_id": row["actor_id"], "actor_kind": row["actor_kind"], "session_id": row["session_id"], "created_at": row["created_at"]})
                if row["previous_event_hash"] != previous or row["event_hash"] != expected_hash:
                    issues.append("event hash chain mismatch")
            except Exception:
                issues.append("event payload is not canonical JSON")
            previous = row["event_hash"]; expected_sequence += 1
        return {"ok": not issues, "event_count": len(rows), "last_event_hash": previous, "issues": sorted(set(issues))}

    def _verify_objects(self, connection: sqlite3.Connection, *, project_id: str, run_id: str) -> dict[str, Any]:
        objects = self._object_rows(connection, project_id, run_id); relations = self._relation_rows(connection, project_id, run_id)
        issues: list[str] = []
        identity_rows = list(connection.execute("SELECT DISTINCT i.stable_id, i.kind FROM max_canonical_objects i JOIN max_run_object_memberships m ON m.project_id=i.project_id AND m.version_id IN (SELECT version_id FROM max_canonical_object_versions WHERE stable_id=i.stable_id AND project_id=i.project_id) WHERE i.project_id=? AND m.run_id=? ORDER BY i.stable_id", (project_id, run_id)))
        identities = {row["stable_id"]: row["kind"] for row in identity_rows}
        versions_by_id: dict[str, set[str]] = {}
        for item in objects:
            kind_value = str(getattr(item.kind, "value", item.kind))
            versions_by_id.setdefault(item.stable_id, set()).add(kind_value)
            if identities.get(item.stable_id) != kind_value:
                issues.append("canonical identity is missing or has a different kind")
        for stable_id in identities:
            if stable_id not in versions_by_id:
                issues.append("canonical identity has no immutable version")
        for item in objects:
            result = validate_canonical_object(item)
            issues.extend(issue.code for issue in result.issues)
        for item in relations:
            result = validate_canonical_relation(item)
            issues.extend(issue.code for issue in result.issues)
            endpoint_count = connection.execute("SELECT COUNT(*) FROM max_run_object_memberships WHERE run_id=? AND version_id IN (?, ?)", (run_id, item.source_version_id, item.target_version_id)).fetchone()[0]
            if endpoint_count != 2:
                issues.append("relation endpoint is not a member of this Run")
        for membership in connection.execute("SELECT * FROM max_run_object_memberships WHERE run_id=? ORDER BY version_id", (run_id,)):
            expected_hash = _hash({"run_id": run_id, "project_id": membership["project_id"], "version_id": membership["version_id"], "change_set_id": membership["adopted_by_change_set_id"]})
            legacy_hash = _hash({"run_id": run_id, "project_id": membership["project_id"], "version_id": membership["version_id"], "legacy": True})
            if membership["membership_hash"] not in {expected_hash, legacy_hash}:
                issues.append("object membership hash mismatch")
        for membership in connection.execute("SELECT * FROM max_run_relation_memberships WHERE run_id=? ORDER BY relation_id", (run_id,)):
            expected_hash = _hash({"run_id": run_id, "project_id": membership["project_id"], "relation_id": membership["relation_id"], "change_set_id": membership["adopted_by_change_set_id"]})
            legacy_hash = _hash({"run_id": run_id, "project_id": membership["project_id"], "relation_id": membership["relation_id"], "legacy": True})
            if membership["membership_hash"] not in {expected_hash, legacy_hash}:
                issues.append("relation membership hash mismatch")
        try:
            state = rebuild_research_state(objects, relations, project_id=project_id, run_id=run_id)
            state_hash = state.state_hash
        except Exception:
            state_hash = None; issues.append("canonical graph cannot be rebuilt")
        membership_objects = connection.execute("SELECT COUNT(*) FROM max_run_object_memberships WHERE run_id=?", (run_id,)).fetchone()[0]
        membership_relations = connection.execute("SELECT COUNT(*) FROM max_run_relation_memberships WHERE run_id=?", (run_id,)).fetchone()[0]
        return {"ok": not issues, "object_identities": len(identities), "object_versions": len(objects), "relations": len(relations), "object_memberships": int(membership_objects), "relation_memberships": int(membership_relations), "state_hash": state_hash, "issues": sorted(set(issues))}

    def _verify_transition_results(self, connection: sqlite3.Connection, *, run_id: str) -> dict[str, Any]:
        rows = list(connection.execute("SELECT * FROM max_run_transition_results WHERE run_id=? ORDER BY resulting_state_version", (run_id,)))
        issues: list[str] = []
        expected_prior = 1
        previous_status = RunStatus.AWAITING_START_APPROVAL.value
        last_status = previous_status
        for row in rows:
            if int(row["prior_state_version"]) != expected_prior:
                issues.append("transition result state versions are not contiguous")
            if row["from_status"] != previous_status:
                issues.append("transition result predecessor status is inconsistent")
            try:
                payload = _loads(row["transition_json"])
                if _hash(payload) != row["transition_hash"]:
                    issues.append("transition result hash mismatch")
                if not isinstance(payload, Mapping) or set(payload) - {"new_state", "approval_consumption"} or "new_state" not in payload:
                    raise ValueError("transition result has unsupported fields")
                transition = RunTransitionResult(new_state=payload["new_state"], approval_consumption=payload.get("approval_consumption"))
                new_state = transition.new_state
                if new_state.run_id != run_id or new_state.state_version != int(row["resulting_state_version"]):
                    issues.append("transition result state binding is inconsistent")
                if row["to_status"] != str(getattr(new_state.status, "value", new_state.status)):
                    issues.append("transition result target status is inconsistent")
                last_status = str(getattr(new_state.status, "value", new_state.status))
            except Exception:
                issues.append("transition result JSON is invalid")
                last_status = row["to_status"]
            expected_prior = int(row["resulting_state_version"])
            previous_status = last_status
        current = connection.execute("SELECT status, state_version FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
        if current is None:
            issues.append("transition result run is missing")
        else:
            if int(current["state_version"]) != expected_prior:
                issues.append("transition result ledger does not reach current state version")
            if current["status"] != last_status:
                issues.append("transition result ledger does not reach current status")
        return {"ok": not issues, "transition_count": len(rows), "last_status": last_status, "issues": sorted(set(issues))}

    def _verify_checkpoints(self, connection: sqlite3.Connection, *, run_id: str) -> dict[str, Any]:
        rows = list(connection.execute("SELECT checkpoint_json FROM max_checkpoints WHERE run_id=? ORDER BY lineage_version", (run_id,)))
        issues: list[str] = []
        values: list[Checkpoint] = []
        for row in rows:
            try: values.append(Checkpoint.from_mapping(_loads(row[0])))
            except Exception: issues.append("checkpoint JSON is invalid")
        if values:
            result = validate_checkpoint_lineage(values); issues.extend(issue.code for issue in result.issues)
        pointer = connection.execute("SELECT checkpoint_id FROM max_checkpoint_current WHERE run_id=?", (run_id,)).fetchone()
        if len({item.checkpoint_id for item in values}) != len(values): issues.append("checkpoint IDs are duplicated")
        if pointer is not None and pointer["checkpoint_id"] not in {item.checkpoint_id for item in values}: issues.append("current checkpoint pointer is orphaned")
        run = connection.execute("SELECT current_checkpoint_id, current_state_hash FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
        if run is None:
            issues.append("checkpoint run is missing")
        else:
            pointer_id = pointer["checkpoint_id"] if pointer else None
            if pointer_id != run["current_checkpoint_id"]:
                issues.append("current checkpoint pointer is not bound to the Run State")
            if pointer_id is not None:
                checkpoint_row = connection.execute("SELECT state_hash FROM max_checkpoints WHERE checkpoint_id=?", (pointer_id,)).fetchone()
                if checkpoint_row is None or checkpoint_row["state_hash"] != run["current_state_hash"]:
                    issues.append("current checkpoint state hash is not bound to the Run State")
        return {"ok": not issues, "checkpoint_count": len(values), "current_checkpoint_id": pointer["checkpoint_id"] if pointer else None, "issues": sorted(set(issues))}

    def _verify_change_sets(self, connection: sqlite3.Connection, *, run_id: str) -> dict[str, Any]:
        rows = list(connection.execute("SELECT * FROM max_canonical_change_sets WHERE run_id=? ORDER BY created_at, change_set_id", (run_id,)))
        issues: list[str] = []
        for row in rows:
            try:
                payload = _loads(row["change_set_json"])
                if _hash(payload) != row["change_set_hash"]:
                    issues.append("canonical change set hash mismatch")
                if payload.get("run_id") != run_id or payload.get("project_id") != row["project_id"] or payload.get("expected_output_state_hash") != row["expected_output_state_hash"]:
                    issues.append("canonical change set binding is inconsistent")
                if connection.execute("SELECT 1 FROM max_iterations WHERE iteration_id=? AND run_id=?", (row["iteration_id"], run_id)).fetchone() is None:
                    issues.append("canonical change set iteration is missing")
            except Exception:
                issues.append("canonical change set JSON is invalid")
        return {"ok": not issues, "change_set_count": len(rows), "issues": sorted(set(issues))}

    def verify_run(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True, verify_schema=False)
        try:
            try:
                schema_manifest = verify_schema_manifest(connection)
            except Exception:
                schema_manifest = {
                    "ok": False,
                    "schema_version": CONTROL_SCHEMA_VERSION,
                    "object_counts": {},
                    "issues": ["Max schema manifest verification failed"],
                }
            row = self._run_row(connection, run_id); state = self._run_state(row)
            chain = self._verify_event_chain(connection, run_id=run_id)
            objects = self._verify_objects(connection, project_id=row["project_id"], run_id=run_id)
            transitions = self._verify_transition_results(connection, run_id=run_id)
            checkpoints = self._verify_checkpoints(connection, run_id=run_id)
            change_sets = self._verify_change_sets(connection, run_id=run_id)
            budget: dict[str, Any]
            try: budget = {"ok": True, **self._budget_reconstruct_connection(connection, run_id=run_id)}
            except MaxControlError as exc: budget = {"ok": False, "issues": [str(exc)]}
            state_row = connection.execute("SELECT state_hash FROM max_research_states WHERE run_id=?", (run_id,)).fetchone()
            state_binding_ok = state_row is not None and state_row["state_hash"] == state.current_state_hash == objects.get("state_hash")
            approval_count = connection.execute("SELECT COUNT(*) AS count FROM max_approval_consumptions WHERE run_id=?", (run_id,)).fetchone()["count"]
            approval_ok = (
                approval_count == 1
                or (
                    approval_count == 0
                    and state.status in {RunStatus.AWAITING_START_APPROVAL, RunStatus.CANCELLED}
                    and state.approval_id is None
                    and state.approval_consumption_id is None
                    and state.approval_consumed_at is None
                )
            )
            issues = list(schema_manifest.get("issues", ())) + list(chain["issues"]) + list(objects["issues"]) + list(transitions["issues"]) + list(checkpoints["issues"]) + list(change_sets["issues"]) + list(budget.get("issues", []))
            if not state_binding_ok: issues.append("run state does not bind the canonical Research State")
            if not approval_ok: issues.append("approval consumption ledger is inconsistent with run state")
            # RunnerPersistence owns the MR-2A append-only chain.  Import it
            # lazily to keep the repository/runner modules acyclic at import
            # time while ensuring every public verify path includes it.
            try:
                from .runner import RunnerPersistence
                runner = RunnerPersistence(self).verify_run(run_id=run_id)
            except Exception:
                runner = {"ok": False, "issues": ["runner verification failed"]}
            issues.extend(str(item) for item in runner.get("issues", ()))
            try:
                from ..provider.store import ProviderStore
                provider = ProviderStore(self).verify(run_id=run_id)
            except Exception:
                provider = {"ok": False, "schema_version": CONTROL_SCHEMA_VERSION, "run_id": run_id, "issues": ["provider verification failed"]}
            try:
                from ..scheduler.service import ForegroundScheduler
                verifier_actor = Actor("mr2b0-verifier", "mr2b0-verifier-session", "worker", "verifier", "research-kb-mr2b0")
                scheduler = ForegroundScheduler(self, verifier_actor, provider_store=ProviderStore(self)).verify(run_id=run_id)
            except Exception:
                scheduler = {"ok": False, "run_id": run_id, "issues": ["scheduler verification failed"]}
            try:
                from ..scheduler.worker import WorkerControl
                worker = WorkerControl(self).verify(run_id=run_id)
            except Exception:
                worker = {"ok": False, "run_id": run_id, "issues": ["worker control verification failed"]}
            try:
                from ..scheduler.acquisition import AcquisitionControl
                acquisition = AcquisitionControl(self).verify(run_id=run_id)
            except Exception:
                acquisition = {"ok": False, "run_id": run_id, "issues": ["acquisition control verification failed"]}
            try:
                from ..long_run import LongRunAuthorizationStore, SourceEgressStore
                long_run = LongRunAuthorizationStore(self).verify(run_id=run_id)
                source_egress = SourceEgressStore(self).verify(run_id=run_id)
            except Exception:
                long_run = {"ok": False, "run_id": run_id, "issues": ["long-run verification failed"]}
                source_egress = {"ok": False, "run_id": run_id, "issues": ["source-egress verification failed"]}
            issues.extend(str(item) for item in provider.get("issues", ()))
            issues.extend(str(item) for item in scheduler.get("issues", ()))
            issues.extend(str(item) for item in worker.get("issues", ()))
            issues.extend(str(item) for item in acquisition.get("issues", ()))
            issues.extend(str(item) for item in long_run.get("issues", ()))
            issues.extend(str(item) for item in source_egress.get("issues", ()))
            return {"ok": not issues and bool(schema_manifest.get("ok", False)) and bool(runner.get("ok", False)) and bool(provider.get("ok", False)) and bool(scheduler.get("ok", False)) and bool(worker.get("ok", False)) and bool(acquisition.get("ok", False)) and bool(long_run.get("ok", False)) and bool(source_egress.get("ok", False)), "schema_version": CONTROL_SCHEMA_VERSION, "schema_manifest": schema_manifest, "run": self._run_summary_from_state(state), "event_chain": chain, "transition_results": transitions, "canonical_graph": objects, "checkpoint_lineage": checkpoints, "change_sets": change_sets, "budget": budget, "runner": runner, "provider": provider, "scheduler": scheduler, "worker": worker, "acquisition": acquisition, "long_run": long_run, "source_egress": source_egress, "approval_consumptions": int(approval_count), "issues": sorted(set(issues))}
        finally:
            connection.close()

    def status(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            row = self._run_row(connection, run_id); state = self._run_state(row)
            lease_row = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
            lease = None
            if lease_row is not None:
                lease = {"owner_id": lease_row["owner_id"], "session_id": lease_row["session_id"], "fencing_token": lease_row["fencing_token"], "expires_at": lease_row["expires_at"], "active": bool(lease_row["owner_id"] and _parse_timestamp(lease_row["expires_at"]) and _parse_timestamp(lease_row["expires_at"]) > _utc_now(self.clock) and not lease_row["released_at"])}
            budget = self._budget_reconstruct_connection(connection, run_id=run_id)
            event_count = connection.execute("SELECT COUNT(*) AS count FROM max_events WHERE run_id=?", (run_id,)).fetchone()["count"]
            return {"run": self._run_summary_from_state(state), "lease": lease, "budget": {key: budget[key] for key in ("limits", "used", "reserved", "available")}, "event_count": int(event_count), "recent_event_types": [row[0] for row in connection.execute("SELECT event_type FROM max_events WHERE run_id=? ORDER BY sequence_no DESC LIMIT 5", (run_id,))][::-1]}
        finally:
            connection.close()

    def list_objects(self, *, project_id: str, run_id: str | None = None) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            if run_id is None:
                raise MaxControlError("canonical reads require an explicit Run")
            row = self._run_row(connection, run_id); self._require_project_run(row, project_id)
            objects = self._object_rows(connection, project_id, run_id); relations = self._relation_rows(connection, project_id, run_id)
            return {"project_id": project_id, "objects": [model_to_dict(item) for item in objects], "relations": [model_to_dict(item) for item in relations]}
        finally:
            connection.close()


__all__ = [
    "IterationRecordInput",
    "MaxControlRepository",
    "MaxControlError",
    "MaxControlNotInitialized",
    "MaxResearchSettings",
    "normalize_budget_amount",
    "normalize_budget_limits",
]
