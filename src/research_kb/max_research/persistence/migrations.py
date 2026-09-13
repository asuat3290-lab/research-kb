"""Fixed, independent migrations for the Max Research control database."""

from __future__ import annotations

import re
import sqlite3
import json
import hashlib
from pathlib import Path
from typing import Callable, Iterable

from ..._resources import PackagedResourceError, read_json_resource
from ..contract import CanonicalObject, CanonicalRelation, canonical_json, canonical_sha256, make_stable_id, rebuild_research_state
from .version import CONTROL_SCHEMA_VERSION


MIGRATION_DIR = Path(__file__).resolve().parent.parent / "migrations"
_MIGRATION_RE = re.compile(r"^(?P<version>[0-9]{3})_(?P<name>[a-z0-9_]+)\.sql$")


def load_migration_release_manifest() -> dict[str, object]:
    try:
        manifest = read_json_resource("max_research", "migration_release_manifest_v1.json")
    except PackagedResourceError as exc:
        raise RuntimeError("Max migration release manifest is unavailable") from exc
    if (
        manifest.get("schema") != "max-migration-release-manifest/v1"
        or manifest.get("manifest_version") != 1
        or manifest.get("control_schema_version") != CONTROL_SCHEMA_VERSION
        or not isinstance(manifest.get("migrations"), list)
    ):
        raise RuntimeError("Max migration release manifest is invalid")
    return manifest


def validate_migration_release(migration_dir: Path | None = None) -> tuple[tuple[int, str, Path], ...]:
    """Validate package migration bytes before any database write."""

    manifest = load_migration_release_manifest()
    expected = manifest["migrations"]
    if not all(isinstance(item, dict) for item in expected):
        raise RuntimeError("Max migration release manifest is invalid")
    directory = Path(migration_dir) if migration_dir is not None else MIGRATION_DIR
    files = migration_files(directory)
    expected_by_version: dict[int, tuple[str, str]] = {}
    for item in expected:
        try:
            version = int(item["version"])
            name = str(item["name"])
            digest = str(item["sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("Max migration release manifest is invalid") from exc
        if version in expected_by_version or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("Max migration release manifest is invalid")
        expected_by_version[version] = (name, digest)
    if sorted(expected_by_version) != list(range(1, CONTROL_SCHEMA_VERSION + 1)) or len(files) != CONTROL_SCHEMA_VERSION:
        raise RuntimeError("Max migration release manifest does not match supported migrations")
    for version, name, path in files:
        expected_name, expected_hash = expected_by_version.get(version, ("", ""))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.name != expected_name or name != Path(expected_name).stem[4:] or digest != expected_hash:
            raise RuntimeError("Max migration release manifest does not match packaged migration bytes")
    return files


def migration_files(directory: Path | None = None) -> tuple[tuple[int, str, Path], ...]:
    files: list[tuple[int, str, Path]] = []
    selected_dir = Path(directory) if directory is not None else MIGRATION_DIR
    if not selected_dir.is_dir():
        raise RuntimeError("Max control migration package data is missing")
    for path in sorted(selected_dir.glob("*.sql")):
        match = _MIGRATION_RE.fullmatch(path.name)
        if match is None:
            raise RuntimeError("invalid Max control migration filename")
        files.append((int(match.group("version")), match.group("name"), path))
    if not files:
        raise RuntimeError("Max control migration package data is empty")
    versions = [item[0] for item in files]
    if versions != list(range(1, len(versions) + 1)):
        raise RuntimeError("Max control migration versions must be contiguous from 1")
    return tuple(files)


def validate_schema_ledger(
    connection: sqlite3.Connection, *, require_current: bool = False
) -> tuple[int, ...]:
    """Validate the applied migration ledger without changing it."""

    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='max_schema_migrations'"
    ).fetchone()
    if exists is None:
        if require_current:
            raise RuntimeError("Max control migration ledger is unavailable")
        return ()
    rows = list(connection.execute("SELECT version, name FROM max_schema_migrations ORDER BY version"))
    versions = [int(row[0]) for row in rows]
    if len(set(versions)) != len(versions):
        raise RuntimeError("Max control migration ledger contains a duplicate version")
    if any(version > CONTROL_SCHEMA_VERSION for version in versions):
        raise RuntimeError("Max control database schema is newer than this release")
    if versions and versions != list(range(1, max(versions) + 1)):
        raise RuntimeError("Max control migration ledger contains a version gap")
    manifest = load_migration_release_manifest()
    expected_names = {
        int(item["version"]): Path(str(item["name"])).stem[4:]
        for item in manifest["migrations"]
        if isinstance(item, dict) and "version" in item and "name" in item
    }
    for version, name in rows:
        if expected_names.get(int(version)) != str(name):
            raise RuntimeError("Max control migration ledger does not match this release")
    if require_current and versions != list(range(1, CONTROL_SCHEMA_VERSION + 1)):
        raise RuntimeError("Max control database schema is not current")
    return tuple(versions)


def _statements(sql: str) -> Iterable[str]:
    """Yield complete SQLite statements, including trigger bodies."""

    buffer = ""
    for line in sql.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            buffer = ""
            if statement and not all(
                part.strip().startswith("--") or not part.strip()
                for part in statement.splitlines()
            ):
                yield statement
    if buffer.strip():
        yield buffer.strip()


def _backfill_schema_v2(connection: sqlite3.Connection) -> None:
    """Derive only facts that schema-1 immutable history proves.

    This is deliberately fixed code, not a user supplied SQL migration.  A
    legacy object with no unambiguous append event is rejected so an upgrade
    can never guess which same-project Run owns it.
    """

    def loads(value: str):
        return json.loads(value)

    object_runs: dict[str, set[tuple[str, str]]] = {}
    relation_runs: dict[str, set[tuple[str, str]]] = {}
    for row in connection.execute("SELECT run_id, event_type, payload_json FROM max_events ORDER BY run_id, sequence_no"):
        try:
            payload = loads(row["payload_json"])
            if not isinstance(payload, dict):
                continue
            if row["event_type"] == "canonical_version_appended" and isinstance(payload.get("version_id"), str):
                project_row = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (row["run_id"],)).fetchone()
                if project_row is not None:
                    object_runs.setdefault(payload["version_id"], set()).add((row["run_id"], project_row[0]))
            elif row["event_type"] == "canonical_relation_appended" and isinstance(payload.get("relation_id"), str):
                project_row = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (row["run_id"],)).fetchone()
                if project_row is not None:
                    relation_runs.setdefault(payload["relation_id"], set()).add((row["run_id"], project_row[0]))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise RuntimeError("schema-1 immutable event payload cannot determine Max membership")

    now = "1970-01-01T00:00:00.000Z"
    object_rows = list(connection.execute("SELECT version_id, project_id FROM max_canonical_object_versions"))
    for row in object_rows:
        owners = object_runs.get(row["version_id"], set())
        if len(owners) != 1 or next(iter(owners))[1] != row["project_id"]:
            raise RuntimeError("schema-1 canonical object ownership is unbound or ambiguous")
        run_id, project_id = next(iter(owners))
        membership_hash = canonical_sha256({"run_id": run_id, "project_id": project_id, "version_id": row["version_id"], "legacy": True})
        connection.execute(
            "INSERT INTO max_run_object_memberships(run_id, project_id, version_id, adopted_by_change_set_id, adopted_at, actor_id, actor_kind, actor_session, membership_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, project_id, row["version_id"], "schema1-upgrade", now, "schema1-upgrade", "system", "schema1-upgrade", membership_hash),
        )

    relation_rows = list(connection.execute("SELECT relation_id, project_id, source_version_id, target_version_id FROM max_canonical_relations"))
    for row in relation_rows:
        owners = relation_runs.get(row["relation_id"], set())
        if len(owners) != 1 or next(iter(owners))[1] != row["project_id"]:
            raise RuntimeError("schema-1 canonical relation ownership is unbound or ambiguous")
        run_id, project_id = next(iter(owners))
        endpoints = connection.execute(
            "SELECT COUNT(*) FROM max_run_object_memberships WHERE run_id=? AND version_id IN (?, ?)",
            (run_id, row["source_version_id"], row["target_version_id"]),
        ).fetchone()[0]
        if endpoints != 2:
            raise RuntimeError("schema-1 relation endpoints are not owned by the relation Run")
        membership_hash = canonical_sha256({"run_id": run_id, "project_id": project_id, "relation_id": row["relation_id"], "legacy": True})
        connection.execute(
            "INSERT INTO max_run_relation_memberships(run_id, project_id, relation_id, adopted_by_change_set_id, adopted_at, actor_id, actor_kind, actor_session, membership_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, project_id, row["relation_id"], "schema1-upgrade", now, "schema1-upgrade", "system", "schema1-upgrade", membership_hash),
        )

    # The old ledger has enough fields for a deterministic legacy request
    # binding.  The immutable trigger is disabled only inside this migration
    # transaction and recreated before commit.
    connection.execute("DROP TRIGGER IF EXISTS max_budget_no_update")
    for row in connection.execute("SELECT entry_id, run_id, operation, amount_json, reservation_id, provenance_json FROM max_budget_ledger"):
        provenance = loads(row["provenance_json"])
        if row["operation"] == "usage" and isinstance(provenance, dict) and not provenance.get("receipt_hash"):
            provenance = {**provenance, "legacy": True}
            connection.execute("UPDATE max_budget_ledger SET provenance_json=? WHERE entry_id=?", (canonical_json(provenance), row["entry_id"]))
        request_hash = canonical_sha256({
            "operation": row["operation"], "amount": loads(row["amount_json"]),
            "reservation_id": None if row["operation"] == "reserve" else row["reservation_id"], "provenance": provenance,
            "run_id": row["run_id"], "iteration_id": None, "legacy": True,
        })
        connection.execute("UPDATE max_budget_ledger SET request_hash=? WHERE entry_id=?", (request_hash, row["entry_id"]))
    connection.execute("CREATE TRIGGER max_budget_no_update BEFORE UPDATE ON max_budget_ledger BEGIN SELECT RAISE(ABORT, 'Max budget ledger is append-only'); END")

    # Preserve the old begin rows while giving completed/aborted rows a typed
    # outcome.  An open pointer is only valid when there is exactly one open
    # begin row for a Run.
    for row in connection.execute("SELECT * FROM max_iterations WHERE status IN ('completed','aborted') ORDER BY run_id, sequence_no"):
        outcome_id = canonical_sha256({"iteration_id": row["iteration_id"], "legacy": True})[:48]
        outcome = {
            "iteration_id": row["iteration_id"], "run_id": row["run_id"], "status": row["status"],
            "input_state_hash": row["input_state_hash"], "output_state_hash": row["output_state_hash"],
            "legacy": True,
        }
        connection.execute(
            "INSERT INTO max_iteration_outcomes(outcome_id, iteration_id, run_id, project_id, status, input_state_hash, output_state_hash, outcome_json, outcome_hash, claim_snapshots_json, evidence_snapshots_json, counterevidence_snapshots_json, strategy_ledger_json, record_refs_json, budget_delta_json, artifact_summary_json, started_at, finished_at, fencing_token, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (outcome_id, row["iteration_id"], row["run_id"], row["project_id"], row["status"], row["input_state_hash"], row["output_state_hash"], canonical_json(outcome), canonical_sha256(outcome), row["claim_snapshots_json"], row["evidence_snapshots_json"], row["counterevidence_snapshots_json"], row["strategy_ledger_json"], row["record_refs_json"], row["budget_delta_json"], canonical_json({"legacy": True}), row["started_at"], row["finished_at"] or now, row["fencing_token"], row["actor_id"], "legacy", row["actor_session"]),
        )
    for run in connection.execute("SELECT run_id FROM max_runs"):
        open_rows = list(connection.execute("SELECT iteration_id, started_at FROM max_iterations WHERE run_id=? AND status='started' ORDER BY sequence_no", (run["run_id"],)))
        if len(open_rows) > 1:
            raise RuntimeError("schema-1 Run has more than one open iteration")
        if open_rows:
            connection.execute("INSERT INTO max_iteration_current(run_id, iteration_id, set_at) VALUES (?, ?, ?)", (run["run_id"], open_rows[0]["iteration_id"], open_rows[0]["started_at"]))

    # Rebuild initial/run-scoped state after membership has been reconstructed.
    # A legacy run that already has transition history but a mismatching graph
    # is not safe to silently rewrite.
    for run in connection.execute("SELECT * FROM max_runs"):
        objects = tuple(CanonicalObject.from_mapping(loads(item[0])) for item in connection.execute("SELECT v.object_json FROM max_canonical_object_versions v JOIN max_run_object_memberships m ON m.version_id=v.version_id WHERE m.run_id=? ORDER BY v.stable_id, v.version", (run["run_id"],)))
        relations = tuple(CanonicalRelation.from_mapping(loads(item[0])) for item in connection.execute("SELECT r.relation_json FROM max_canonical_relations r JOIN max_run_relation_memberships m ON m.relation_id=r.relation_id WHERE m.run_id=? ORDER BY r.relation_id", (run["run_id"],)))
        rebuilt = rebuild_research_state(objects, relations, project_id=run["project_id"], run_id=run["run_id"])
        if rebuilt.state_hash != run["current_state_hash"]:
            transition_count = connection.execute("SELECT COUNT(*) FROM max_run_transition_results WHERE run_id=?", (run["run_id"],)).fetchone()[0]
            if transition_count:
                raise RuntimeError("schema-1 Run State cannot be safely rebound to recovered membership")
            connection.execute("UPDATE max_research_states SET state_hash=?, state_json=? WHERE run_id=?", (rebuilt.state_hash, canonical_json(rebuilt), run["run_id"]))
            connection.execute("UPDATE max_runs SET current_state_hash=?, run_state_json=? WHERE run_id=?", (rebuilt.state_hash, canonical_json({**loads(run["run_state_json"]), "current_state_hash": rebuilt.state_hash}), run["run_id"]))
            connection.execute("UPDATE max_checkpoints SET state_hash=? WHERE run_id=?", (rebuilt.state_hash, run["run_id"]))


def _backfill_schema_v4(connection: sqlite3.Connection) -> None:
    """Refuse to guess durable runner manifests during a 3->4 upgrade.

    Schema 3 stored the full request/response envelopes.  There is no safe,
    deterministic way to prove that a legacy row can be reduced to the new
    metadata-only manifest without re-reading provider material.  Empty
    control stores therefore upgrade normally; any legacy runner history fails
    closed and must be exported/reviewed explicitly by an administrator.
    """

    tables = (
        "max_runner_plans", "max_model_call_intents", "max_model_call_results",
        "max_runner_recovery_decisions", "max_runner_attempt_outcomes",
    )
    if any(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables):
        raise RuntimeError("schema-3 runner history cannot be safely backfilled to metadata-only schema-4 manifests")


_SCHEMA6_TABLES = {
    "max_provider_pricing_snapshots", "max_provider_profiles", "max_run_provider_bindings",
    "max_live_execution_grants", "max_live_execution_grant_consumptions", "max_provider_call_records",
    "max_provider_usage_attestations", "max_scheduler_policies", "max_scheduler_sessions",
    "max_scheduler_current", "max_scheduler_ticks",
}
_SCHEMA6_APPEND_ONLY_TRIGGERS = {
    "max_provider_pricing_no_update", "max_provider_pricing_no_delete", "max_provider_profiles_no_update",
    "max_provider_profiles_no_delete", "max_run_provider_bindings_no_update", "max_run_provider_bindings_no_delete",
    "max_live_grants_no_update", "max_live_grants_no_delete", "max_live_consumptions_no_update",
    "max_live_consumptions_no_delete", "max_provider_calls_no_update", "max_provider_calls_no_delete",
    "max_provider_attestations_no_update", "max_provider_attestations_no_delete", "max_scheduler_policies_no_update",
    "max_scheduler_policies_no_delete", "max_scheduler_sessions_no_update", "max_scheduler_sessions_no_delete",
    "max_scheduler_ticks_no_update", "max_scheduler_ticks_no_delete",
}

_SCHEMA7_TABLES = {
    "max_provider_grant_usage_current", "max_provider_call_claims",
    "max_provider_call_claim_events", "max_provider_call_claim_current",
}
_SCHEMA7_APPEND_ONLY_TRIGGERS = {
    "max_provider_call_claims_no_update", "max_provider_call_claims_no_delete",
    "max_provider_call_claim_events_no_update", "max_provider_call_claim_events_no_delete",
}

_SCHEMA8_TABLES = {
    "max_provider_dispatch_attempts", "max_provider_dispatch_attempt_current",
    "max_provider_dispatch_attempt_events", "max_provider_call_attempt_bindings",
    "max_provider_call_results",
}
_SCHEMA8_APPEND_ONLY_TRIGGERS = {
    "max_provider_dispatch_attempts_no_update", "max_provider_dispatch_attempts_no_delete",
    "max_provider_dispatch_attempt_events_no_update", "max_provider_dispatch_attempt_events_no_delete",
    "max_provider_call_attempt_bindings_no_update", "max_provider_call_attempt_bindings_no_delete",
    "max_provider_call_results_no_update", "max_provider_call_results_no_delete",
}

_SCHEMA9_TABLES = {
    "max_live_network_policies", "max_live_network_authorizations",
    "max_live_network_authorization_current",
    "max_live_network_authorization_consumptions",
    "max_live_network_access_events", "max_live_network_attempt_records",
}
_SCHEMA9_APPEND_ONLY_TRIGGERS = {
    "max_live_network_policies_no_update", "max_live_network_policies_no_delete",
    "max_live_network_authorizations_no_update", "max_live_network_authorizations_no_delete",
    "max_live_network_consumptions_no_update", "max_live_network_consumptions_no_delete",
    "max_live_network_access_events_no_update", "max_live_network_access_events_no_delete",
    "max_live_network_attempt_records_no_update", "max_live_network_attempt_records_no_delete",
}

_SCHEMA10_TABLES = {
    "max_live_dispatch_permits", "max_live_dispatch_permit_current",
    "max_live_dispatch_permit_events",
}
_SCHEMA10_APPEND_ONLY_TRIGGERS = {
    "max_live_dispatch_permits_no_update", "max_live_dispatch_permits_no_delete",
    "max_live_dispatch_permit_events_no_update", "max_live_dispatch_permit_events_no_delete",
}

_SCHEMA11_TABLES = {
    "max_live_authorization_bundles", "max_live_authorization_bundle_members",
    "max_live_authorization_bundle_current", "max_live_authorization_assignments",
    "max_live_authorization_bundle_events", "max_live_iteration_approvals",
    "max_live_iteration_approval_consumptions",
}
_SCHEMA11_APPEND_ONLY_TRIGGERS = {
    "max_live_authorization_bundles_no_update", "max_live_authorization_bundles_no_delete",
    "max_live_authorization_bundle_members_no_update", "max_live_authorization_bundle_members_no_delete",
    "max_live_authorization_assignments_no_update", "max_live_authorization_assignments_no_delete",
    "max_live_authorization_bundle_events_no_update", "max_live_authorization_bundle_events_no_delete",
    "max_live_iteration_approvals_no_update", "max_live_iteration_approvals_no_delete",
    "max_live_iteration_approval_consumptions_no_update", "max_live_iteration_approval_consumptions_no_delete",
}

_SCHEMA12_TABLES = {
    "max_worker_commands", "max_worker_command_consumptions", "max_worker_heartbeats",
    "max_worker_current", "max_acquisition_requests", "max_acquisition_current",
    "max_acquisition_worker_grants", "max_acquisition_worker_grant_consumptions",
    "max_acquisition_claims", "max_acquisition_validation_receipts",
    "max_acquisition_stage_receipts", "max_acquisition_events",
}
_SCHEMA12_APPEND_ONLY_TRIGGERS = {
    "max_worker_commands_no_update", "max_worker_commands_no_delete",
    "max_worker_command_consumptions_no_update", "max_worker_command_consumptions_no_delete",
    "max_worker_heartbeats_no_update", "max_worker_heartbeats_no_delete",
    "max_acquisition_requests_no_update", "max_acquisition_requests_no_delete",
    "max_acquisition_worker_grants_no_update", "max_acquisition_worker_grants_no_delete",
    "max_acquisition_worker_grant_consumptions_no_update", "max_acquisition_worker_grant_consumptions_no_delete",
    "max_acquisition_claims_no_update", "max_acquisition_claims_no_delete",
    "max_acquisition_validation_receipts_no_update", "max_acquisition_validation_receipts_no_delete",
    "max_acquisition_stage_receipts_no_update", "max_acquisition_stage_receipts_no_delete",
    "max_acquisition_events_no_update", "max_acquisition_events_no_delete",
}

_SCHEMA13_TABLES = {
    "max_long_run_windows", "max_long_run_window_current", "max_long_run_usage",
    "max_long_run_iteration_permits", "max_long_run_permit_consumptions",
    "max_long_run_events",
}
_SCHEMA13_APPEND_ONLY_TRIGGERS = {
    "max_long_run_windows_no_update", "max_long_run_windows_no_delete",
    "max_long_run_usage_no_update", "max_long_run_usage_no_delete",
    "max_long_run_iteration_permits_no_update", "max_long_run_iteration_permits_no_delete",
    "max_long_run_permit_consumptions_no_update", "max_long_run_permit_consumptions_no_delete",
    "max_long_run_events_no_update", "max_long_run_events_no_delete",
}

_SCHEMA14_TABLES = {
    "max_source_egress_policies", "max_source_packet_requests", "max_source_handles",
    "max_canonical_source_packets", "max_source_packet_receipts",
    "max_source_packet_consumptions", "max_source_egress_events",
}
_SCHEMA14_APPEND_ONLY_TRIGGERS = {
    "max_source_egress_policies_no_update", "max_source_egress_policies_no_delete",
    "max_source_packet_requests_no_update", "max_source_packet_requests_no_delete",
    "max_source_handles_no_update", "max_source_handles_no_delete",
    "max_canonical_source_packets_no_update", "max_canonical_source_packets_no_delete",
    "max_source_packet_receipts_no_update", "max_source_packet_receipts_no_delete",
    "max_source_packet_consumptions_no_update", "max_source_packet_consumptions_no_delete",
    "max_source_egress_events_no_update", "max_source_egress_events_no_delete",
}

_SCHEMA15_TABLES = {
    "max_long_run_execution_bindings",
    "max_long_run_iteration_execution_bindings",
    "max_long_run_iteration_source_sets",
    "max_long_run_iteration_usage_receipts",
    "max_long_run_renewal_approvals",
}
_SCHEMA15_APPEND_ONLY_TRIGGERS = {
    "max_long_run_execution_bindings_no_update", "max_long_run_execution_bindings_no_delete",
    "max_long_run_iteration_execution_bindings_no_update", "max_long_run_iteration_execution_bindings_no_delete",
    "max_long_run_iteration_source_sets_no_update", "max_long_run_iteration_source_sets_no_delete",
    "max_long_run_iteration_usage_receipts_no_update", "max_long_run_iteration_usage_receipts_no_delete",
    "max_long_run_renewal_approvals_no_update", "max_long_run_renewal_approvals_no_delete",
}

_SCHEMA16_TABLES = {
    "max_live_canary_previews", "max_live_canary_approvals",
    "max_live_canary_approval_current", "max_live_canary_approval_consumptions",
    "max_live_canary_execution_permits", "max_live_canary_execution_permit_current",
    "max_live_canary_outcomes", "max_live_canary_events",
}
_SCHEMA16_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_previews_no_update", "max_live_canary_previews_no_delete",
    "max_live_canary_approvals_no_update", "max_live_canary_approvals_no_delete",
    "max_live_canary_approval_consumptions_no_update", "max_live_canary_approval_consumptions_no_delete",
    "max_live_canary_execution_permits_no_update", "max_live_canary_execution_permits_no_delete",
    "max_live_canary_outcomes_no_update", "max_live_canary_outcomes_no_delete",
    "max_live_canary_events_no_update", "max_live_canary_events_no_delete",
}

_SCHEMA17_TABLES = {
    "max_live_canary_authority_bindings",
}
_SCHEMA17_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_authority_bindings_no_update",
    "max_live_canary_authority_bindings_no_delete",
}

_SCHEMA18_TABLES = {
    "max_live_canary_request_manifests",
    "max_live_canary_source_permits",
    "max_live_canary_source_permit_current",
    "max_live_canary_source_permit_events",
    "max_live_canary_review_marks",
}
_SCHEMA18_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_request_manifests_no_update",
    "max_live_canary_request_manifests_no_delete",
    "max_live_canary_source_permits_no_update",
    "max_live_canary_source_permits_no_delete",
    "max_live_canary_source_permit_events_no_update",
    "max_live_canary_source_permit_events_no_delete",
    "max_live_canary_review_marks_no_update",
    "max_live_canary_review_marks_no_delete",
}

_SCHEMA19_TABLES = {
    "max_live_execution_grant_closures",
}
_SCHEMA19_APPEND_ONLY_TRIGGERS = {
    "max_live_execution_grant_closures_no_update",
    "max_live_execution_grant_closures_no_delete",
}

_SCHEMA20_TABLES = {
    "max_live_canary_preparation_snapshots",
    "max_live_canary_preparation_snapshot_current",
    "max_live_canary_preparation_snapshot_events",
    "max_live_canary_preparation_previews",
    "max_live_canary_preparation_approvals",
    "max_live_canary_preparation_approval_consumptions",
    "max_live_canary_jit_execution_authorities",
    "max_live_canary_preparation_dns_authorities",
    "max_live_canary_preparation_dns_requests",
}
_SCHEMA20_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_preparation_snapshots_no_update",
    "max_live_canary_preparation_snapshots_no_delete",
    "max_live_canary_preparation_snapshot_events_no_update",
    "max_live_canary_preparation_snapshot_events_no_delete",
    "max_live_canary_preparation_previews_no_update",
    "max_live_canary_preparation_previews_no_delete",
    "max_live_canary_preparation_approvals_no_update",
    "max_live_canary_preparation_approvals_no_delete",
    "max_live_canary_preparation_approval_consumptions_no_update",
    "max_live_canary_preparation_approval_consumptions_no_delete",
    "max_live_canary_jit_execution_authorities_no_update",
    "max_live_canary_jit_execution_authorities_no_delete",
    "max_live_canary_preparation_dns_authorities_no_update",
    "max_live_canary_preparation_dns_authorities_no_delete",
    "max_live_canary_preparation_dns_requests_no_update",
    "max_live_canary_preparation_dns_requests_no_delete",
}

_SCHEMA21_TABLES = {
    "max_live_canary_native_dns_receipts",
    "max_live_canary_native_approvals",
    "max_live_canary_native_approval_consumptions",
    "max_live_canary_native_approval_revocations",
    "max_live_canary_native_jit_authorities",
    "max_live_canary_native_jit_events",
}
_SCHEMA21_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_native_dns_receipts_no_update",
    "max_live_canary_native_dns_receipts_no_delete",
    "max_live_canary_native_approvals_no_update",
    "max_live_canary_native_approvals_no_delete",
    "max_live_canary_native_approval_consumptions_no_update",
    "max_live_canary_native_approval_consumptions_no_delete",
    "max_live_canary_native_approval_revocations_no_update",
    "max_live_canary_native_approval_revocations_no_delete",
    "max_live_canary_native_jit_authorities_no_update",
    "max_live_canary_native_jit_authorities_no_delete",
    "max_live_canary_native_jit_events_no_update",
    "max_live_canary_native_jit_events_no_delete",
}

_SCHEMA22_TABLES = {
    "max_runner_preparation_handoffs",
    "max_runner_preparation_handoff_current",
    "max_runner_preparation_handoff_events",
}
_SCHEMA22_APPEND_ONLY_TRIGGERS = {
    "max_runner_preparation_handoffs_no_update",
    "max_runner_preparation_handoffs_no_delete",
    "max_runner_preparation_handoff_events_no_update",
    "max_runner_preparation_handoff_events_no_delete",
}

_SCHEMA23_TABLES = {
    "max_live_canary_dns_attempts",
    "max_live_canary_dns_attempt_consumptions",
    "max_live_canary_dns_attempt_events",
    "max_live_canary_dns_attempt_current",
    "max_live_canary_dns_attempt_receipts",
}
_SCHEMA23_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_dns_attempts_no_update",
    "max_live_canary_dns_attempts_no_delete",
    "max_live_canary_dns_attempt_consumptions_no_update",
    "max_live_canary_dns_attempt_consumptions_no_delete",
    "max_live_canary_dns_attempt_events_no_update",
    "max_live_canary_dns_attempt_events_no_delete",
    "max_live_canary_dns_attempt_receipts_no_update",
    "max_live_canary_dns_attempt_receipts_no_delete",
}

_SCHEMA24_TABLES = {
    "max_live_canary_approval_previews",
    "max_live_canary_native_approvals_v2",
    "max_live_canary_native_approval_v2_consumptions",
}
_SCHEMA24_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_approval_previews_no_update",
    "max_live_canary_approval_previews_no_delete",
    "max_live_canary_native_approvals_v2_no_update",
    "max_live_canary_native_approvals_v2_no_delete",
    "max_live_canary_native_approval_v2_consumptions_no_update",
    "max_live_canary_native_approval_v2_consumptions_no_delete",
}

_SCHEMA25_TABLES = {
    "max_live_canary_native_execution_previews",
    "max_live_canary_native_execution_authorizations",
    "max_live_canary_native_execution_authorization_consumptions",
    "max_live_canary_native_source_permits",
    "max_live_canary_native_source_permit_current",
    "max_live_canary_native_source_permit_events",
    "max_live_canary_native_live_jit_authorities",
    "max_live_canary_native_live_jit_events",
}
_SCHEMA25_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_native_execution_previews_no_update",
    "max_live_canary_native_execution_previews_no_delete",
    "max_live_canary_native_execution_authorizations_no_update",
    "max_live_canary_native_execution_authorizations_no_delete",
    "max_live_canary_native_execution_consumptions_no_update",
    "max_live_canary_native_execution_consumptions_no_delete",
    "max_live_canary_native_source_permits_no_update",
    "max_live_canary_native_source_permits_no_delete",
    "max_live_canary_native_source_permit_events_no_update",
    "max_live_canary_native_source_permit_events_no_delete",
    "max_live_canary_native_live_jit_authorities_no_update",
    "max_live_canary_native_live_jit_authorities_no_delete",
    "max_live_canary_native_live_jit_events_no_update",
    "max_live_canary_native_live_jit_events_no_delete",
}

_SCHEMA26_TABLES = {
    "max_live_canary_native_execution_previews",
    "max_live_canary_native_execution_preview_current",
    "max_live_canary_native_execution_preview_events",
}
_SCHEMA26_APPEND_ONLY_TRIGGERS = {
    "max_live_canary_native_execution_previews_no_update",
    "max_live_canary_native_execution_previews_no_delete",
    "max_live_canary_native_execution_preview_events_no_update",
    "max_live_canary_native_execution_preview_events_no_delete",
}

_SCHEMA27_TABLES = {
    "max_live_network_policy_bindings",
}
_SCHEMA27_APPEND_ONLY_TRIGGERS = {
    "max_live_network_policy_bindings_no_update",
    "max_live_network_policy_bindings_no_delete",
}

_SCHEMA28_TABLES = {
    "max_live_execution_capsule_previews",
    "max_live_execution_capsule_current",
    "max_live_execution_capsule_consumptions",
    "max_live_execution_capsule_events",
}
_SCHEMA28_APPEND_ONLY_TRIGGERS = {
    "max_live_execution_capsule_previews_no_update",
    "max_live_execution_capsule_previews_no_delete",
    "max_live_execution_capsule_consumptions_no_update",
    "max_live_execution_capsule_consumptions_no_delete",
    "max_live_execution_capsule_events_no_update",
    "max_live_execution_capsule_events_no_delete",
}

_SCHEMA29_TABLES = {
    "max_agent_host_profiles",
    "max_execution_backend_profiles",
    "max_run_execution_bindings",
    "max_run_execution_binding_current",
    "max_backend_handoff_approvals",
    "max_backend_handoff_current",
    "max_backend_handoff_events",
    "max_portability_events",
    "max_normalized_agent_results",
}
_SCHEMA29_APPEND_ONLY_TRIGGERS = {
    "max_agent_host_profiles_no_update",
    "max_agent_host_profiles_no_delete",
    "max_execution_backend_profiles_no_update",
    "max_execution_backend_profiles_no_delete",
    "max_run_execution_bindings_no_update",
    "max_run_execution_bindings_no_delete",
    "max_backend_handoff_approvals_no_update",
    "max_backend_handoff_approvals_no_delete",
    "max_backend_handoff_events_no_update",
    "max_backend_handoff_events_no_delete",
    "max_portability_events_no_update",
    "max_portability_events_no_delete",
    "max_normalized_agent_results_no_update",
    "max_normalized_agent_results_no_delete",
}

_SCHEMA30_TABLES = {
    "max_normalized_agent_results_v2",
    "max_backend_handoff_lineage",
    "max_rehydration_packets",
    "max_rehydration_packet_acks",
    "max_rehydration_packet_events",
    "max_portability_profile_status_events",
    "max_host_installations",
}
_SCHEMA30_APPEND_ONLY_TRIGGERS = {
    "max_normalized_agent_results_v2_no_update",
    "max_normalized_agent_results_v2_no_delete",
    "max_backend_handoff_lineage_no_update",
    "max_backend_handoff_lineage_no_delete",
    "max_rehydration_packets_no_update",
    "max_rehydration_packets_no_delete",
    "max_rehydration_packet_acks_no_update",
    "max_rehydration_packet_acks_no_delete",
    "max_rehydration_packet_events_no_update",
    "max_rehydration_packet_events_no_delete",
    "max_portability_profile_status_events_no_update",
    "max_portability_profile_status_events_no_delete",
    "max_host_installations_no_update",
    "max_host_installations_no_delete",
}

_SCHEMA31_TABLES = {
    "max_portability_quiescence_snapshots",
    "max_rehydration_packet_manifest_items",
    "max_rehydration_packet_target_acks",
    "max_portability_invocation_bindings",
    "max_portability_result_bindings",
    "max_host_installation_attestations",
}
_SCHEMA31_APPEND_ONLY_TRIGGERS = {
    "max_portability_quiescence_snapshots_no_update",
    "max_portability_quiescence_snapshots_no_delete",
    "max_rehydration_packet_manifest_items_no_update",
    "max_rehydration_packet_manifest_items_no_delete",
    "max_rehydration_packet_target_acks_no_update",
    "max_rehydration_packet_target_acks_no_delete",
    "max_portability_invocation_bindings_no_update",
    "max_portability_invocation_bindings_no_delete",
    "max_portability_result_bindings_no_update",
    "max_portability_result_bindings_no_delete",
    "max_host_installation_attestations_no_update",
    "max_host_installation_attestations_no_delete",
}

_SCHEMA32_TABLES = {
    "max_external_agent_sessions",
    "max_external_agent_session_events",
    "max_external_agent_work_packets",
    "max_external_agent_work_current",
    "max_external_agent_work_claims",
    "max_external_agent_work_claim_current",
    "max_external_agent_work_claim_events",
    "max_external_agent_results",
    "max_external_agent_events",
}
_SCHEMA32_APPEND_ONLY_TRIGGERS = {
    "max_external_agent_sessions_no_update",
    "max_external_agent_sessions_no_delete",
    "max_external_agent_session_events_no_update",
    "max_external_agent_session_events_no_delete",
    "max_external_agent_work_packets_no_update",
    "max_external_agent_work_packets_no_delete",
    "max_external_agent_work_claims_no_update",
    "max_external_agent_work_claims_no_delete",
    "max_external_agent_work_claim_events_no_update",
    "max_external_agent_work_claim_events_no_delete",
    "max_external_agent_results_no_update",
    "max_external_agent_results_no_delete",
    "max_external_agent_events_no_update",
    "max_external_agent_events_no_delete",
}

# This is the normalized sqlite_master SQL fingerprint of the 025 parent
# table.  It is intentionally checked before the rebuild so a future drift or
# an unexpected database copy fails closed instead of being "repaired".
_SCHEMA25_PREVIEW_TABLE_SQL_SHA256 = "46259e1a45da8d9946438d6ea26d5acb590cb08da622a7993669f0b9403b0b29"
_SCHEMA25_PREVIEW_COLUMNS = (
    "execution_preview_id", "approval_id", "approval_hash", "approval_preview_id",
    "approval_preview_hash", "project_id", "run_id", "snapshot_id", "snapshot_hash",
    "preparation_preview_id", "preparation_preview_hash", "handoff_id", "handoff_hash",
    "request_manifest_hash", "dns_attempt_id", "dns_receipt_id", "dns_receipt_hash",
    "bounded_dns_result_hash", "provider_profile_hash", "model_identity", "pricing_hash",
    "network_policy_hash", "source_policy_hash", "endpoint_origin_hash",
    "credential_reference_hash", "release_identity_hash", "source_tree_hash", "wheel_hash",
    "budget_hash", "current_state_hash", "current_state_version", "human_cost_ceiling",
    "profile_worst_case_cost", "effective_cost_cap", "max_provider_calls", "max_input_tokens",
    "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens", "state",
    "execution_phrase_hash", "execution_preview_json", "execution_preview_hash", "created_at",
    "expires_at", "actor_id", "actor_kind", "actor_session",
)


def _verify_schema6_shape(connection: sqlite3.Connection) -> None:
    """Verify the fixed MR-2B0 schema shape before the migration commits."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA6_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-2B0 migration did not create its fixed control tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA6_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-2B0 migration did not create its fixed append-only triggers")


def _verify_schema7_shape(connection: sqlite3.Connection) -> None:
    """Verify the fixed MR-2B0R authority/budget shape before commit."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA7_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-2B0R migration did not create its fixed authority tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA7_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-2B0R migration did not create its fixed append-only triggers")


def _backfill_schema_v8(connection: sqlite3.Connection) -> None:
    """Create one physical attempt for each already durable MR-2B0R claim.

    Schema 7 counted one immutable logical claim per provider dispatch.  A
    deterministic one-to-one backfill preserves that historical fact while
    making future physical attempts explicit.  No provider response or source
    content is reconstructed; old calls without a stored proposal remain
    non-replayable and therefore fail closed at the adapter boundary.
    """

    now = "1970-01-01T00:00:00.000Z"
    rows = connection.execute(
        "SELECT c.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id, "
        "u.actual_input_tokens, u.actual_output_tokens, u.actual_cache_read_tokens, "
        "u.actual_reasoning_tokens, u.actual_cost_units "
        "FROM max_provider_call_claims c JOIN max_provider_call_claim_current u "
        "ON u.claim_id=c.claim_id ORDER BY c.created_at, c.claim_id"
    ).fetchall()
    for row in rows:
        existing = connection.execute(
            "SELECT attempt_id FROM max_provider_dispatch_attempts WHERE claim_id=? AND physical_attempt_no=1",
            (row["claim_id"],),
        ).fetchone()
        if existing is not None:
            continue
        attempt_value = {
            "claim_id": row["claim_id"], "grant_id": row["grant_id"],
            "grant_consumption_id": row["grant_consumption_id"], "run_id": row["run_id"],
            "project_id": row["project_id"], "logical_call_id": row["logical_call_id"],
            "intent_id": row["intent_id"], "iteration_id": row["iteration_id"],
            "intent_hash": row["intent_hash"], "request_hash": row["request_hash"],
            "profile_hash": row["profile_hash"], "model_identity": row["model_identity"],
            "pricing_hash": row["pricing_hash"], "idempotency_key": row["idempotency_key"],
            "physical_attempt_no": 1, "fencing_token": int(row["fencing_token"]),
            "owner_id": row["owner_id"], "owner_session": row["owner_session"],
            "reserved_input_tokens": int(row["reserved_input_tokens"]),
            "reserved_output_tokens": int(row["reserved_output_tokens"]),
            "reserved_cache_read_tokens": int(row["reserved_cache_read_tokens"]),
            "reserved_reasoning_tokens": int(row["reserved_reasoning_tokens"]),
            "reserved_cost_units": int(row["reserved_cost_units"]), "legacy": True,
        }
        attempt_hash = canonical_sha256(attempt_value)
        attempt_id = "provider_dispatch_attempt_" + attempt_hash[:48]
        connection.execute(
            "INSERT INTO max_provider_dispatch_attempts(attempt_id, claim_id, grant_id, grant_consumption_id, run_id, project_id, logical_call_id, intent_id, iteration_id, intent_hash, request_hash, profile_hash, model_identity, pricing_hash, idempotency_key, physical_attempt_no, fencing_token, owner_id, owner_session, reserved_input_tokens, reserved_output_tokens, reserved_cache_read_tokens, reserved_reasoning_tokens, reserved_cost_units, attempt_json, attempt_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (attempt_id, row["claim_id"], row["grant_id"], row["grant_consumption_id"], row["run_id"], row["project_id"], row["logical_call_id"], row["intent_id"], row["iteration_id"], row["intent_hash"], row["request_hash"], row["profile_hash"], row["model_identity"], row["pricing_hash"], row["idempotency_key"], 1, int(row["fencing_token"]), row["owner_id"], row["owner_session"], int(row["reserved_input_tokens"]), int(row["reserved_output_tokens"]), int(row["reserved_cache_read_tokens"]), int(row["reserved_reasoning_tokens"]), int(row["reserved_cost_units"]), canonical_json(attempt_value), attempt_hash, row["created_at"] or now),
        )
        state = {
            "claimed": "reserved", "dispatching": "dispatching", "dispatched": "succeeded",
            "attested": "settled", "settled": "settled", "failed": "failed",
            "unknown": "unknown", "disputed": "disputed", "released": "cancelled",
        }.get(str(row["state"]))
        if state is None:
            raise RuntimeError("schema-7 provider claim has an unsupported state")
        actual = {
            "input_tokens": int(row["actual_input_tokens"]), "output_tokens": int(row["actual_output_tokens"]),
            "cache_read_tokens": int(row["actual_cache_read_tokens"]), "reasoning_tokens": int(row["actual_reasoning_tokens"]),
            "cost_units": int(row["actual_cost_units"]),
        }
        current_value = {
            "attempt_id": attempt_id, "claim_id": row["claim_id"], "state": state,
            "provider_call_id": row["provider_call_id"], "call_record_id": row["call_record_id"],
            "attestation_id": row["attestation_id"], "actual": actual, "legacy": True,
        }
        current_hash = canonical_sha256(current_value)
        connection.execute(
            "INSERT INTO max_provider_dispatch_attempt_current(attempt_id, claim_id, grant_id, run_id, state, provider_call_id, call_record_id, attestation_id, actual_input_tokens, actual_output_tokens, actual_cache_read_tokens, actual_reasoning_tokens, actual_cost_units, current_json, current_hash, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (attempt_id, row["claim_id"], row["grant_id"], row["run_id"], state, row["provider_call_id"], row["call_record_id"], row["attestation_id"], actual["input_tokens"], actual["output_tokens"], actual["cache_read_tokens"], actual["reasoning_tokens"], actual["cost_units"], canonical_json(current_value), current_hash, row["created_at"] or now),
        )
        event_value = {"attempt_id": attempt_id, "claim_id": row["claim_id"], "run_id": row["run_id"], "sequence_no": 1, "event_type": state, "payload_hash": current_hash, "previous_event_hash": None, "created_at": row["created_at"] or now, "legacy": True}
        event_hash = canonical_sha256(event_value)
        connection.execute(
            "INSERT INTO max_provider_dispatch_attempt_events(attempt_event_id, attempt_id, claim_id, run_id, sequence_no, event_type, payload_json, payload_hash, previous_event_hash, event_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, 1, ?, ?, ?, NULL, ?, ?, ?, ?, ?)",
            ("provider_dispatch_attempt_event_" + event_hash[:48], attempt_id, row["claim_id"], row["run_id"], state, canonical_json(current_value), current_hash, event_hash, row["created_at"] or now, "schema8-upgrade", "system", "schema8-upgrade"),
        )
        if row["call_record_id"]:
            call = connection.execute("SELECT * FROM max_provider_call_records WHERE call_record_id=?", (row["call_record_id"],)).fetchone()
            if call is not None:
                binding_value = {"call_record_id": call["call_record_id"], "attempt_id": attempt_id, "run_id": row["run_id"], "project_id": row["project_id"], "legacy": True}
                binding_hash = canonical_sha256(binding_value)
                connection.execute(
                    "INSERT OR IGNORE INTO max_provider_call_attempt_bindings(call_record_id, attempt_id, run_id, project_id, binding_json, binding_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (call["call_record_id"], attempt_id, row["run_id"], row["project_id"], canonical_json(binding_value), binding_hash, call["created_at"] or now),
                )


def _verify_schema8_shape(connection: sqlite3.Connection) -> None:
    """Verify the fixed MR-2B0R2 physical-attempt shape before commit."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA8_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-2B0R2 migration did not create its physical attempt tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA8_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-2B0R2 migration did not create its append-only physical attempt triggers")


def _verify_schema9_shape(connection: sqlite3.Connection) -> None:
    """Verify the fixed MR-2B1 live authorization shape before commit."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA9_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-2B1 migration did not create its live authorization tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA9_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-2B1 migration did not create its append-only live authorization triggers")


def _verify_schema10_shape(connection: sqlite3.Connection) -> None:
    """Verify the fixed MR-2B1A permit shape before the migration commits."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA10_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-2B1A migration did not create its live dispatch permit tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA10_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-2B1A migration did not create its append-only live dispatch permit triggers")


def _verify_schema11_shape(connection: sqlite3.Connection) -> None:
    """Verify the fixed MR-2B2 live authorization bundle shape."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if _SCHEMA11_TABLES - tables:
        raise RuntimeError("MR-2B2 migration did not create its live authorization bundle tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    if _SCHEMA11_APPEND_ONLY_TRIGGERS - triggers:
        raise RuntimeError("MR-2B2 migration did not create its append-only bundle triggers")


def _verify_schema12_shape(connection: sqlite3.Connection) -> None:
    """Verify the fixed MR-3 worker/acquisition shape."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if _SCHEMA12_TABLES - tables:
        raise RuntimeError("MR-3 migration did not create its worker/acquisition tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    if _SCHEMA12_APPEND_ONLY_TRIGGERS - triggers:
        raise RuntimeError("MR-3 migration did not create its append-only worker/acquisition triggers")


def _verify_schema13_shape(connection: sqlite3.Connection) -> None:
    """Verify bounded long-run authority and permit storage."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if _SCHEMA13_TABLES - tables:
        raise RuntimeError("MR-4A migration did not create its long-run authority tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    if _SCHEMA13_APPEND_ONLY_TRIGGERS - triggers:
        raise RuntimeError("MR-4A migration did not create its append-only long-run triggers")


def _verify_schema14_shape(connection: sqlite3.Connection) -> None:
    """Verify canonical source-egress storage and its append-only boundary."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if _SCHEMA14_TABLES - tables:
        raise RuntimeError("MR-4A migration did not create its source-egress tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    if _SCHEMA14_APPEND_ONLY_TRIGGERS - triggers:
        raise RuntimeError("MR-4A migration did not create its append-only source-egress triggers")


def _verify_schema15_shape(connection: sqlite3.Connection) -> None:
    """Verify the MR-4A.1 authority-binding and renewal shape."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if _SCHEMA15_TABLES - tables:
        raise RuntimeError("MR-4A.1 migration did not create its authority-binding tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    if _SCHEMA15_APPEND_ONLY_TRIGGERS - triggers:
        raise RuntimeError("MR-4A.1 migration did not create its append-only authority triggers")


def _verify_schema16_shape(connection: sqlite3.Connection) -> None:
    """Verify the one-shot live-canary authority shape."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if _SCHEMA16_TABLES - tables:
        raise RuntimeError("MR-4B0 migration did not create its live-canary authority tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    if _SCHEMA16_APPEND_ONLY_TRIGGERS - triggers:
        raise RuntimeError("MR-4B0 migration did not create its append-only live-canary triggers")


def _verify_schema17_shape(connection: sqlite3.Connection) -> None:
    """Verify the server-owned MR-4B1A authority snapshot shape."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA17_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1A migration did not create its authority binding table")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA17_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1A migration did not create its append-only authority triggers")


def _verify_schema18_shape(connection: sqlite3.Connection) -> None:
    """Verify the MR-4B1A-R request/source closure shape."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA18_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1A-R migration did not create its request/source tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA18_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1A-R migration did not create its append-only request/source triggers")


def _verify_schema19_shape(connection: sqlite3.Connection) -> None:
    """Verify terminal grant closure storage before the migration commits."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA19_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1B-v4R migration did not create grant closure storage")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA19_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1B-v4R migration did not create append-only grant closure triggers")


def _verify_schema20_shape(connection: sqlite3.Connection) -> None:
    """Verify lifetime-separated preparation and JIT storage before commit."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA20_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1B-v11R1 migration did not create preparation/JIT tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA20_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1B-v11R1 migration did not create append-only preparation/JIT triggers")


def _verify_schema21_shape(connection: sqlite3.Connection) -> None:
    """Verify the native Preparation-to-JIT bridge shape before commit."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA21_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1B-v12R1 migration did not create native bridge tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA21_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1B-v12R1 migration did not create native append-only triggers")


def _verify_schema22_shape(connection: sqlite3.Connection) -> None:
    """Verify durable preparation handoff storage before commit."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA22_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1B-v13R1 migration did not create preparation handoff tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA22_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1B-v13R1 migration did not create preparation handoff append-only triggers")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(max_runner_call_group_current)")}
    if "lifecycle_state" not in columns:
        raise RuntimeError("MR-4B1B-v13R1 migration did not add the runner lifecycle projection")


def _verify_schema23_shape(connection: sqlite3.Connection) -> None:
    """Verify durable DNS attempt/receipt storage before the migration commits."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA23_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1B-v14R3 migration did not create durable DNS attempt storage")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA23_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1B-v14R3 migration did not create append-only DNS controls")
    event_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_live_canary_dns_attempt_events)")}
    required = {"failure_stage", "previous_event_hash", "event_hash"}
    if not required.issubset(event_columns):
        raise RuntimeError("MR-4B1B-v14R3 migration did not create the typed event chain")


def _verify_schema24_shape(connection: sqlite3.Connection) -> None:
    """Verify the server-owned Live Approval Preview boundary."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA24_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1B-v15R2 migration did not create Live Approval Preview tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA24_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1B-v15R2 migration did not create append-only Preview/Approval controls")
    preview_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_live_canary_approval_previews)")}
    required = {
        "approval_preview_id", "snapshot_state_hash", "preparation_preview_id",
        "handoff_id", "dns_attempt_id", "dns_receipt_id", "bounded_dns_result_hash",
        "confirmation_phrase_hash", "approval_expires_at", "preview_expires_at",
        "approval_preview_hash", "state",
    }
    if not required.issubset(preview_columns):
        raise RuntimeError("MR-4B1B-v15R2 migration did not create the complete Preview binding")


def _verify_schema25_shape(connection: sqlite3.Connection) -> None:
    """Verify the Native JIT-to-live execution bridge boundary."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA25_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1B-v16R3 migration did not create native live execution tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA25_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1B-v16R3 migration did not create native live append-only controls")
    preview_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_live_canary_native_execution_previews)")}
    required = {"execution_preview_hash", "execution_phrase_hash", "approval_id", "dns_receipt_hash", "release_identity_hash", "effective_cost_cap"}
    if not required.issubset(preview_columns):
        raise RuntimeError("MR-4B1B-v16R3 migration did not create the complete execution Preview binding")
    jit_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_live_canary_native_live_jit_authorities)")}
    if not {"grant_id", "network_authorization_id", "dispatch_permit_id", "source_permit_id", "fencing_token"}.issubset(jit_columns):
        raise RuntimeError("MR-4B1B-v16R3 migration did not create the complete JIT authority binding")


def _normalized_sql_sha256(value: str) -> str:
    return hashlib.sha256(re.sub(r"\s+", " ", value.strip()).encode("utf-8")).hexdigest()


def _schema25_preview_precondition(connection: sqlite3.Connection) -> None:
    """Refuse migration 026 unless the immutable 025 parent is recognized."""

    ledger = connection.execute(
        "SELECT MAX(version) FROM max_schema_migrations"
    ).fetchone()
    if ledger is None or ledger[0] != 25:
        raise RuntimeError("MR-4B1C requires an exact Max schema-25 database")
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='max_live_canary_native_execution_previews'"
    ).fetchone()
    if row is None or not isinstance(row[0], str):
        raise RuntimeError("MR-4B1C schema-25 Preview table is missing")
    if _SCHEMA25_PREVIEW_TABLE_SQL_SHA256 == "REPLACED_BY_RELEASE_BUILD":
        raise RuntimeError("MR-4B1C schema-25 Preview fingerprint is not released")
    if _normalized_sql_sha256(row[0]) != _SCHEMA25_PREVIEW_TABLE_SQL_SHA256:
        raise RuntimeError("MR-4B1C schema-25 Preview table fingerprint drifted")
    columns = [row[1] for row in connection.execute("PRAGMA table_info(max_live_canary_native_execution_previews)")]
    if columns != list(_SCHEMA25_PREVIEW_COLUMNS):
        raise RuntimeError("MR-4B1C schema-25 Preview columns drifted")


def _capture_schema25_preview_rows(connection: sqlite3.Connection) -> tuple[int, tuple[str, ...]]:
    selected = ",".join(_SCHEMA25_PREVIEW_COLUMNS)
    rows = list(connection.execute(
        f"SELECT {selected} FROM max_live_canary_native_execution_previews ORDER BY execution_preview_id"
    ))
    digests = tuple(
        canonical_sha256({key: row[key] for key in row.keys()})
        for row in rows
    )
    return len(rows), digests


def _backfill_schema26(
    connection: sqlite3.Connection,
    *,
    statement_hook: Callable[[int, str], None] | None = None,
    statement_count: int = 0,
) -> None:
    """Create current/lineage projections without rewriting history."""

    rows = list(connection.execute(
        "SELECT * FROM max_live_canary_native_execution_previews ORDER BY approval_id,generation,created_at,execution_preview_id"
    ))
    for row in rows:
        current = {
            "approval_id": row["approval_id"],
            "execution_preview_id": row["execution_preview_id"],
            "execution_preview_hash": row["execution_preview_hash"],
            "generation": int(row["generation"]),
            "state": row["state"],
            "expires_at": row["expires_at"],
            "updated_at": row["created_at"],
        }
        connection.execute(
            "INSERT INTO max_live_canary_native_execution_preview_current(approval_id,execution_preview_id,execution_preview_hash,generation,state,expires_at,current_json,current_hash,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (row["approval_id"], row["execution_preview_id"], row["execution_preview_hash"], int(row["generation"]), row["state"], row["expires_at"], canonical_json(current), canonical_sha256(current), row["created_at"]),
        )
        if statement_hook is not None:
            statement_hook(statement_count, "SCHEMA26_CURRENT_PROJECTION_BACKFILL")
        payload = {
            "execution_preview_id": row["execution_preview_id"],
            "approval_id": row["approval_id"],
            "run_id": row["run_id"],
            "execution_preview_hash": row["execution_preview_hash"],
            "generation": int(row["generation"]),
            "supersedes_execution_preview_id": row["supersedes_execution_preview_id"],
            "supersedes_execution_preview_hash": row["supersedes_execution_preview_hash"],
            "renewal_reason": row["renewal_reason"],
        }
        payload_hash = canonical_sha256(payload)
        identity = {
            "execution_preview_id": row["execution_preview_id"],
            "approval_id": row["approval_id"],
            "run_id": row["run_id"],
            "sequence_no": 1,
            "event_type": "created",
            "payload_hash": payload_hash,
            "previous_event_hash": None,
            "created_at": row["created_at"],
        }
        event_hash = canonical_sha256(identity)
        event_id = make_stable_id("native_execution_preview_event", event_hash[:64])
        connection.execute(
            "INSERT INTO max_live_canary_native_execution_preview_events(event_id,execution_preview_id,approval_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, row["execution_preview_id"], row["approval_id"], row["run_id"], 1, "created", canonical_json(payload), payload_hash, None, event_hash, row["created_at"], row["actor_id"], row["actor_kind"], row["actor_session"]),
        )
        if statement_hook is not None:
            statement_hook(statement_count, "SCHEMA26_EVENT_BACKFILL")


def _verify_schema26_shape(connection: sqlite3.Connection) -> None:
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA26_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1C migration did not create renewal projections")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA26_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1C migration did not create append-only renewal controls")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(max_live_canary_native_execution_previews)")}
    required = {"generation", "supersedes_execution_preview_id", "supersedes_execution_preview_hash", "renewal_reason"}
    if not required.issubset(columns):
        raise RuntimeError("MR-4B1C migration did not add lineage columns")
    if connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_preview_current").fetchone()[0] != connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_previews").fetchone()[0]:
        raise RuntimeError("MR-4B1C current projection backfill is incomplete")
    if connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_preview_events").fetchone()[0] != connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_previews").fetchone()[0]:
        raise RuntimeError("MR-4B1C lineage event backfill is incomplete")


def _verify_schema27_shape(connection: sqlite3.Connection) -> None:
    """Verify the durable Live Network Policy binding boundary."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA27_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-4B1C-NP0 migration did not create policy bindings")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA27_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-4B1C-NP0 migration did not create append-only policy binding controls")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(max_live_network_policy_bindings)")}
    required = {
        "binding_id", "run_id", "project_id", "profile_hash", "network_policy_hash",
        "policy_hash", "provider_name", "model_identity", "endpoint_origin_hash",
        "credential_reference_hash", "release_identity_hash", "dns_policy_hash",
        "max_getaddrinfo_calls", "max_dns_candidates", "binding_json", "binding_hash",
        "created_at", "authority_id", "authority_kind", "authority_session",
    }
    if not required.issubset(columns):
        raise RuntimeError("MR-4B1C-NP0 policy binding columns are incomplete")


def _verify_schema28_shape(connection: sqlite3.Connection) -> None:
    """Verify the compact server-owned execution capsule boundary."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA28_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-CONVERGENCE-DEV18 migration did not create capsule tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA28_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-CONVERGENCE-DEV18 migration did not create append-only capsule controls")
    preview_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_live_execution_capsule_previews)")}
    required_preview = {
        "capsule_id", "capsule_hash", "run_id", "snapshot_id", "preparation_preview_id",
        "handoff_id", "policy_binding_id", "network_policy_hash", "credential_reference_hash",
        "release_identity_hash", "request_manifest_hash", "effective_cost_cap",
        "max_provider_calls", "confirmation_phrase_hash", "capsule_json",
    }
    if not required_preview.issubset(preview_columns):
        raise RuntimeError("MR-CONVERGENCE-DEV18 capsule Preview binding is incomplete")
    current_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_live_execution_capsule_current)")}
    if not {"capsule_id", "capsule_hash", "state", "current_json", "current_hash"}.issubset(current_columns):
        raise RuntimeError("MR-CONVERGENCE-DEV18 capsule current projection is incomplete")


def _verify_schema29_shape(connection: sqlite3.Connection) -> None:
    """Verify the explicit portable host/backend control boundary."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA29_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-PORTABILITY-0 migration did not create portability tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA29_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-PORTABILITY-0 migration did not create append-only portability controls")
    host_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_agent_host_profiles)")}
    if not {
        "host_profile_id", "host_kind", "host_version", "control_surface",
        "capability_manifest_hash", "canonical_skill_hash", "adapter_hash",
        "allowed_operations_json", "profile_json", "profile_hash",
    }.issubset(host_columns):
        raise RuntimeError("MR-PORTABILITY-0 Agent Host profile columns are incomplete")
    backend_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_execution_backend_profiles)")}
    if not {
        "backend_profile_id", "backend_kind", "provider_name", "model_identity",
        "capability_manifest_json", "credential_strategy_json", "pricing_policy_json",
        "profile_json", "profile_hash",
    }.issubset(backend_columns):
        raise RuntimeError("MR-PORTABILITY-0 Execution Backend profile columns are incomplete")
    binding_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_run_execution_bindings)")}
    if not {
        "run_id", "host_profile_id", "backend_profile_id", "backend_profile_hash",
        "capability_manifest_hash", "source_policy_hash", "budget_hash",
        "binding_version", "binding_json", "binding_hash",
    }.issubset(binding_columns):
        raise RuntimeError("MR-PORTABILITY-0 Run Execution binding columns are incomplete")
    handoff_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_backend_handoff_approvals)")}
    if not {
        "old_backend_profile_id", "new_host_profile_id", "new_backend_profile_id", "current_research_state_hash",
        "confirmation_phrase_hash", "handoff_hash", "expires_at",
    }.issubset(handoff_columns):
        raise RuntimeError("MR-PORTABILITY-0 handoff approval columns are incomplete")


def _verify_schema30_shape(connection: sqlite3.Connection) -> None:
    """Verify the additive portability correction boundary."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA30_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-PORTABILITY-0R migration did not create correction tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA30_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-PORTABILITY-0R migration did not create append-only correction controls")
    result_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_normalized_agent_results_v2)")}
    if not {"project_id", "run_id", "binding_id", "iteration_id", "invocation_id", "intent_id", "input_state_hash", "checkpoint_id", "invocation_hash", "result_hash", "attribution_hash"}.issubset(result_columns):
        raise RuntimeError("MR-PORTABILITY-0R result attribution columns are incomplete")
    handoff_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_backend_handoff_lineage)")}
    if not {"generation", "supersedes_handoff_approval_id", "supersedes_handoff_hash", "lineage_hash"}.issubset(handoff_columns):
        raise RuntimeError("MR-PORTABILITY-0R handoff lineage columns are incomplete")
    packet_columns = {row[1] for row in connection.execute("PRAGMA table_info(max_rehydration_packets)")}
    if not {"packet_id", "handoff_approval_id", "new_binding_id", "state_hash", "packet_hash", "state"}.issubset(packet_columns):
        raise RuntimeError("MR-PORTABILITY-0R rehydration packet columns are incomplete")


def _verify_schema31_shape(connection: sqlite3.Connection) -> None:
    """Verify server-owned portability proof material and append-only controls."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA31_TABLES - tables
    if missing_tables:
        raise RuntimeError("MR-PORTABILITY-0R2 migration did not create convergence tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA31_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("MR-PORTABILITY-0R2 migration did not create append-only convergence controls")
    required_columns = {
        "max_portability_quiescence_snapshots": {"snapshot_id", "run_id", "phase", "activity_hash", "snapshot_hash"},
        "max_rehydration_packet_manifest_items": {"manifest_item_id", "packet_id", "ordinal", "item_type", "item_id", "item_hash"},
        "max_rehydration_packet_target_acks": {"target_ack_id", "ack_id", "packet_id", "target_host_profile_id", "manifest_root", "read_complete"},
        "max_portability_invocation_bindings": {"invocation_binding_id", "run_id", "binding_id", "invocation_id", "invocation_hash", "source_kind"},
        "max_portability_result_bindings": {"result_id", "invocation_binding_id", "run_id", "result_hash", "binding_hash"},
        "max_host_installation_attestations": {"attestation_id", "installation_id", "attestation_kind", "verifier_authority", "executable_proof"},
    }
    for table, required in required_columns.items():
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if not required.issubset(columns):
            raise RuntimeError(f"MR-PORTABILITY-0R2 {table} columns are incomplete")


def _verify_schema32_shape(connection: sqlite3.Connection) -> None:
    """Verify the external-Agent work protocol shape before commit."""

    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing_tables = _SCHEMA32_TABLES - tables
    if missing_tables:
        raise RuntimeError("External Agent migration did not create all protocol tables")
    triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    missing_triggers = _SCHEMA32_APPEND_ONLY_TRIGGERS - triggers
    if missing_triggers:
        raise RuntimeError("External Agent migration did not create append-only controls")
    required_columns = {
        "max_external_agent_sessions": {
            "session_id", "connection_id", "project_id", "authenticated_actor_id",
            "authenticated_actor_session", "claimed_agent_id", "auth_method", "session_json", "session_hash",
        },
        "max_external_agent_session_events": {
            "event_id", "session_id", "sequence_no", "event_type", "previous_event_hash", "event_hash",
        },
        "max_external_agent_work_packets": {
            "work_packet_id", "run_id", "project_id", "iteration_id", "round_no",
            "state_version", "state_hash", "source_refs_json", "result_contract_json", "packet_hash",
        },
        "max_external_agent_work_current": {
            "work_packet_id", "run_id", "project_id", "state", "generation", "current_hash",
        },
        "max_external_agent_work_claims": {
            "claim_id", "work_packet_id", "session_id", "generation", "fencing_token_hash", "claim_hash",
        },
        "max_external_agent_work_claim_current": {
            "claim_id", "work_packet_id", "session_id", "state", "current_hash",
        },
        "max_external_agent_work_claim_events": {
            "event_id", "claim_id", "sequence_no", "event_type", "previous_event_hash", "event_hash",
        },
        "max_external_agent_results": {
            "result_id", "work_packet_id", "run_id", "session_id", "claim_id", "idempotency_key",
            "result_hash", "usage_hash", "usage_status", "result_status",
        },
        "max_external_agent_events": {
            "event_id", "stream_key", "sequence_no", "run_id", "project_id", "event_type", "event_hash",
        },
    }
    for table, required in required_columns.items():
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if not required.issubset(columns):
            raise RuntimeError(f"External Agent {table} columns are incomplete")


def apply_migrations(
    connection: sqlite3.Connection,
    *,
    fail_after_statement: int | None = None,
    statement_hook: Callable[[int, str], None] | None = None,
) -> int:
    """Apply only packaged Max migrations in transactions.

    ``fail_after_statement`` and ``statement_hook`` are intentionally small
    test seams.  They let tests prove rollback without editing a migration or
    touching the real pilot database.
    """

    files = validate_migration_release()
    # Read the existing ledger before BEGIN IMMEDIATE.  A future or malformed
    # ledger must not be changed even by the bootstrap CREATE TABLE statement.
    validate_schema_ledger(connection)
    ledger_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='max_schema_migrations'"
    ).fetchone() is not None
    applied_before = (
        {int(row[0]) for row in connection.execute("SELECT version FROM max_schema_migrations")}
        if ledger_exists else set()
    )
    schema26_pending = 26 in {version for version, _, _ in files} and 26 not in applied_before
    schema26_rebuild = schema26_pending and 25 in applied_before
    schema25_preview_snapshot: tuple[int, tuple[str, ...]] | None = None
    if schema26_rebuild:
        _schema25_preview_precondition(connection)
        schema25_preview_snapshot = _capture_schema25_preview_rows(connection)
        # SQLite cannot toggle foreign_keys inside an active transaction.  The
        # controlled rebuild is therefore the one exception: disable checking
        # before BEGIN, validate PRAGMA foreign_key_check inside the same
        # transaction, and restore enforcement before commit.
        connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("BEGIN IMMEDIATE")
    statement_count = 0
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS max_schema_migrations(
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        validate_schema_ledger(connection)
        applied = {
            int(row[0])
            for row in connection.execute("SELECT version FROM max_schema_migrations")
        }
        for version, name, path in files:
            if version in applied:
                continue
            for statement in _statements(path.read_text(encoding="utf-8")):
                connection.execute(statement)
                statement_count += 1
                if statement_hook is not None:
                    statement_hook(statement_count, statement)
                if fail_after_statement is not None and statement_count >= fail_after_statement:
                    raise RuntimeError("injected migration interruption")
            if version == 2:
                _backfill_schema_v2(connection)
            if version == 4:
                _backfill_schema_v4(connection)
            if version == 8:
                _backfill_schema_v8(connection)
            if version == 26:
                _backfill_schema26(connection, statement_hook=statement_hook, statement_count=statement_count)
            connection.execute(
                "INSERT INTO max_schema_migrations(version, name, applied_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                (version, name),
            )
        if any(version == 6 for version, _, _ in files):
            _verify_schema6_shape(connection)
        if any(version == 7 for version, _, _ in files):
            _verify_schema7_shape(connection)
        if any(version == 8 for version, _, _ in files):
            _verify_schema8_shape(connection)
        if any(version == 9 for version, _, _ in files):
            _verify_schema9_shape(connection)
        if any(version == 10 for version, _, _ in files):
            _verify_schema10_shape(connection)
        if any(version == 11 for version, _, _ in files):
            _verify_schema11_shape(connection)
        if any(version == 12 for version, _, _ in files):
            _verify_schema12_shape(connection)
        if any(version == 13 for version, _, _ in files):
            _verify_schema13_shape(connection)
        if any(version == 14 for version, _, _ in files):
            _verify_schema14_shape(connection)
        if any(version == 15 for version, _, _ in files):
            _verify_schema15_shape(connection)
        if any(version == 16 for version, _, _ in files):
            _verify_schema16_shape(connection)
        if any(version == 17 for version, _, _ in files):
            _verify_schema17_shape(connection)
        if any(version == 18 for version, _, _ in files):
            _verify_schema18_shape(connection)
        if any(version == 19 for version, _, _ in files):
            _verify_schema19_shape(connection)
        if any(version == 20 for version, _, _ in files):
            _verify_schema20_shape(connection)
        if any(version == 21 for version, _, _ in files):
            _verify_schema21_shape(connection)
        if any(version == 22 for version, _, _ in files):
            _verify_schema22_shape(connection)
        if any(version == 23 for version, _, _ in files):
            _verify_schema23_shape(connection)
        if any(version == 24 for version, _, _ in files):
            _verify_schema24_shape(connection)
        if any(version == 25 for version, _, _ in files):
            _verify_schema25_shape(connection)
        if any(version == 26 for version, _, _ in files):
            _verify_schema26_shape(connection)
            if schema25_preview_snapshot is not None:
                after_rows = _capture_schema25_preview_rows(connection)
                if after_rows != schema25_preview_snapshot:
                    raise RuntimeError("MR-4B1C historical Preview rows changed during rebuild")
        if any(version == 27 for version, _, _ in files):
            _verify_schema27_shape(connection)
        if any(version == 28 for version, _, _ in files):
            _verify_schema28_shape(connection)
        if any(version == 29 for version, _, _ in files):
            _verify_schema29_shape(connection)
        if any(version == 30 for version, _, _ in files):
            _verify_schema30_shape(connection)
        if any(version == 31 for version, _, _ in files):
            _verify_schema31_shape(connection)
        if any(version == 32 for version, _, _ in files):
            _verify_schema32_shape(connection)
        validate_schema_ledger(connection, require_current=True)
        foreign_key_issues = list(connection.execute("PRAGMA foreign_key_check"))
        if foreign_key_issues:
            raise RuntimeError("MR-4B1C foreign-key check failed during rebuild")
        connection.commit()
    except Exception:
        connection.rollback()
        if schema26_rebuild:
            connection.execute("PRAGMA foreign_keys = ON")
        raise
    if schema26_rebuild:
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise RuntimeError("MR-4B1C could not restore foreign-key enforcement")
        if list(connection.execute("PRAGMA foreign_key_check")):
            raise RuntimeError("MR-4B1C post-commit foreign-key check failed")
    return max((version for version, _, _ in files), default=0)
