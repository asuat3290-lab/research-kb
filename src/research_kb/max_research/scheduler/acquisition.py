"""MR-3 acquisition request control plane.

This module never downloads, OCRs, or ingests a source.  It persists a typed
research gap and, only after a distinct validator/admin reads one explicit
isolated staging directory, creates a server-owned validation receipt.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any, Mapping

from ...policy import Actor
from ..contract import AcquisitionRequest, canonical_json, canonical_sha256, make_stable_id, model_to_dict, validate_acquisition_request
from ..persistence.db import MaxControlError, control_transaction
from ..persistence.repository import MaxControlRepository, _actor_fields, _parse_timestamp, _timestamp, _utc_now
from .staging import STAGING_VALIDATOR_VERSION_HASH, validate_staging_run


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value.lower()):
        raise MaxControlError(f"{name} is not a SHA-256 hash")
    return value.lower()


def _reason(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 2_000 or "\r" in value or "\n" in value:
        raise MaxControlError("acquisition decision reason is invalid")
    return value.strip()


class AcquisitionControl:
    """Durable human/worker handoff for source acquisition."""

    def __init__(self, repository: MaxControlRepository) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("AcquisitionControl requires MaxControlRepository")
        self.repository = repository

    @staticmethod
    def _current_value(*, request_id: str, run_id: str, project_id: str, state: str) -> dict[str, Any]:
        return {"request_id": request_id, "run_id": run_id, "project_id": project_id, "state": state}

    @staticmethod
    def _event(connection: sqlite3.Connection, *, request_id: str, run_id: str, project_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str) -> None:
        payload_value = dict(payload)
        if len(canonical_json(payload_value).encode("utf-8")) > 50_000:
            raise MaxControlError("acquisition event payload is too large")
        previous = connection.execute("SELECT sequence_no, event_hash FROM max_acquisition_events WHERE request_id=? ORDER BY sequence_no DESC LIMIT 1", (request_id,)).fetchone()
        sequence_no = int(previous["sequence_no"]) + 1 if previous is not None else 1
        payload_hash = canonical_sha256(payload_value)
        event_value = {"request_id": request_id, "run_id": run_id, "project_id": project_id, "sequence_no": sequence_no, "event_type": event_type, "payload_hash": payload_hash, "previous_event_hash": previous["event_hash"] if previous is not None else None, "created_at": now}
        event_hash = canonical_sha256(event_value)
        event_id = make_stable_id("acquisition_event", event_hash[:64])
        actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
        connection.execute("INSERT INTO max_acquisition_events(acquisition_event_id, request_id, run_id, project_id, sequence_no, event_type, payload_json, payload_hash, previous_event_hash, event_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (event_id, request_id, run_id, project_id, sequence_no, event_type, canonical_json(payload_value), payload_hash, event_value["previous_event_hash"], event_hash, now, actor_id, actor_kind, actor_session))

    def _set_current(self, connection: sqlite3.Connection, *, row: Mapping[str, Any], state: str, actor: Actor, now: str, payload: Mapping[str, Any]) -> None:
        current = self._current_value(request_id=row["request_id"], run_id=row["run_id"], project_id=row["project_id"], state=state)
        connection.execute("UPDATE max_acquisition_current SET state=?, current_json=?, current_hash=?, updated_at=? WHERE request_id=?", (state, canonical_json(current), canonical_sha256(current), now, row["request_id"]))
        self._event(connection, request_id=row["request_id"], run_id=row["run_id"], project_id=row["project_id"], event_type=state, payload=payload, actor=actor, now=now)
        self.repository._append_event(connection, run_id=row["run_id"], event_type=f"acquisition_{state}", payload={"request_id": row["request_id"], **dict(payload)}, actor=actor, now=now)

    def propose(self, *, request: AcquisitionRequest | Mapping[str, Any], actor: Actor) -> dict[str, Any]:
        if actor.actor_kind == "model":
            raise MaxControlError("raw model output cannot directly propose an acquisition request")
        value = request if isinstance(request, AcquisitionRequest) else AcquisitionRequest.from_mapping(request)
        validation = validate_acquisition_request(value)
        validation.raise_if_invalid()
        mapping = model_to_dict(value)
        request_hash = canonical_sha256(mapping)
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (value.run_id,)).fetchone()
                if run is None or run["project_id"] != value.project_id or run["source_policy_hash"] != value.source_policy_hash or run["status"] not in {"RUNNING", "PAUSED"}:
                    raise MaxControlError("acquisition request is outside the current run/source policy")
                known_ids = {row[0] for row in connection.execute("SELECT stable_id FROM max_canonical_object_versions v JOIN max_run_object_memberships m ON m.version_id=v.version_id WHERE m.run_id=?", (value.run_id,))}
                if any(target not in known_ids for target in value.target_ids):
                    raise MaxControlError("acquisition request target is outside the canonical frontier")
                existing = connection.execute("SELECT request_json, request_hash FROM max_acquisition_requests WHERE request_id=?", (value.request_id,)).fetchone()
                if existing is not None:
                    if existing["request_hash"] != request_hash or json.loads(existing["request_json"]) != mapping:
                        raise MaxControlError("acquisition request ID collision")
                    current = connection.execute("SELECT state FROM max_acquisition_current WHERE request_id=?", (value.request_id,)).fetchone()
                    return {"request_id": value.request_id, "request_hash": request_hash, "state": current["state"], "idempotent": True}
                now = _timestamp(self.repository.clock)
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                connection.execute("INSERT INTO max_acquisition_requests(request_id, run_id, project_id, source_policy_hash, request_json, request_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (value.request_id, value.run_id, value.project_id, value.source_policy_hash, canonical_json(mapping), request_hash, now, actor_id, actor_kind, actor_session))
                current = self._current_value(request_id=value.request_id, run_id=value.run_id, project_id=value.project_id, state="proposed")
                connection.execute("INSERT INTO max_acquisition_current(request_id, run_id, project_id, state, current_json, current_hash, updated_at) VALUES (?, ?, ?, 'proposed', ?, ?, ?)", (value.request_id, value.run_id, value.project_id, canonical_json(current), canonical_sha256(current), now))
                self._event(connection, request_id=value.request_id, run_id=value.run_id, project_id=value.project_id, event_type="proposed", payload={"request_hash": request_hash, "source_policy_hash": value.source_policy_hash, "max_candidates": value.max_candidates}, actor=actor, now=now)
                self.repository._append_event(connection, run_id=value.run_id, event_type="acquisition_proposed", payload={"request_id": value.request_id, "request_hash": request_hash, "source_policy_hash": value.source_policy_hash, "max_candidates": value.max_candidates}, actor=actor, now=now)
            return {"request_id": value.request_id, "request_hash": request_hash, "state": "proposed", "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("acquisition request conflicts with immutable history") from exc
        finally:
            connection.close()

    def decide(
        self,
        *,
        request_id: str,
        decision: str,
        reason: str,
        actor: Actor,
        validation_hash: str | None = None,
        dry_run_manifest_hash: str | None = None,
    ) -> dict[str, Any]:
        if not actor.is_admin or decision not in {"approve", "reject", "cancel", "accept"}:
            raise MaxControlError("acquisition decision requires valid human admin authority")
        reason_hash = canonical_sha256(_reason(reason))
        if decision == "accept":
            validation_hash = _hash(validation_hash, "validation_hash")
            dry_run_manifest_hash = _hash(dry_run_manifest_hash, "dry_run_manifest_hash")
        elif validation_hash is not None or dry_run_manifest_hash is not None:
            raise MaxControlError("validation hashes are only valid for an accept decision")
        transitions = {"approve": ("proposed", "approved"), "reject": (("proposed", "approved", "staged"), "rejected"), "cancel": (("proposed", "approved"), "cancelled"), "accept": ("staged", "accepted")}
        expected, target = transitions[decision]
        expected_states = (expected,) if isinstance(expected, str) else expected
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT r.*, c.state FROM max_acquisition_requests r JOIN max_acquisition_current c ON c.request_id=r.request_id WHERE r.request_id=?", (request_id,)).fetchone()
                if row is None:
                    raise MaxControlError("acquisition request was not found")
                if row["state"] == target:
                    if decision == "accept":
                        receipt = connection.execute("SELECT * FROM max_acquisition_stage_receipts WHERE request_id=?", (request_id,)).fetchone()
                        if receipt is None or receipt["validation_hash"] != validation_hash or receipt["dry_run_manifest_hash"] != dry_run_manifest_hash:
                            raise MaxControlError("accepted acquisition replay differs from its validated projection")
                    return {"request_id": request_id, "state": target, "idempotent": True}
                if row["state"] not in expected_states:
                    raise MaxControlError("acquisition decision is invalid from current state")
                now = _timestamp(self.repository.clock)
                payload: dict[str, Any] = {"reason_hash": reason_hash}
                if decision == "accept":
                    receipt = connection.execute("SELECT * FROM max_acquisition_stage_receipts WHERE request_id=?", (request_id,)).fetchone()
                    if receipt is None or receipt["validation_hash"] != validation_hash or receipt["dry_run_manifest_hash"] != dry_run_manifest_hash:
                        raise MaxControlError("accept requires the exact staged validation and dry-run manifest hashes")
                    payload.update({"receipt_id": receipt["receipt_id"], "receipt_hash": receipt["receipt_hash"], "validation_hash": validation_hash, "dry_run_manifest_hash": dry_run_manifest_hash})
                self._set_current(connection, row=row, state=target, actor=actor, now=now, payload=payload)
            return {"request_id": request_id, "state": target, "idempotent": False}
        finally:
            connection.close()

    def authorize_worker(
        self,
        *,
        request_id: str,
        worker_id: str,
        worker_session: str,
        max_candidates: int,
        max_bytes: int,
        ttl_seconds: int,
        reason: str,
        actor: Actor,
    ) -> dict[str, Any]:
        """Issue one bounded worker grant without borrowing the runner lease."""

        if not actor.is_admin:
            raise MaxControlError("acquisition worker authorization requires human admin authority")
        if any(not isinstance(value, str) or not value.strip() or len(value.strip()) > 256 for value in (worker_id, worker_session)):
            raise MaxControlError("acquisition worker identity is invalid")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (max_candidates, max_bytes, ttl_seconds)):
            raise MaxControlError("acquisition worker grant caps are invalid")
        if max_candidates > 10_000 or max_bytes > 100 * 1024 * 1024 * 1024 or ttl_seconds > 7 * 24 * 60 * 60:
            raise MaxControlError("acquisition worker grant caps exceed hard limits")
        reason_hash = canonical_sha256(_reason(reason))
        worker_id = worker_id.strip(); worker_session = worker_session.strip()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute(
                    "SELECT r.*, c.state FROM max_acquisition_requests r JOIN max_acquisition_current c ON c.request_id=r.request_id WHERE r.request_id=?",
                    (request_id,),
                ).fetchone()
                if row is None or row["state"] != "approved":
                    raise MaxControlError("only an approved acquisition request can authorize a worker")
                request = AcquisitionRequest.from_mapping(json.loads(row["request_json"]))
                if max_candidates > request.max_candidates:
                    raise MaxControlError("worker candidate cap exceeds the approved request")
                existing = connection.execute("SELECT * FROM max_acquisition_worker_grants WHERE request_id=?", (request_id,)).fetchone()
                if existing is not None:
                    expected = {
                        "worker_id": worker_id,
                        "worker_session": worker_session,
                        "max_candidates": max_candidates,
                        "max_bytes": max_bytes,
                        "reason_hash": reason_hash,
                    }
                    if any(existing[key] != value for key, value in expected.items()):
                        raise MaxControlError("acquisition request already has a different worker grant")
                    consumed = connection.execute(
                        "SELECT consumption_id FROM max_acquisition_worker_grant_consumptions WHERE worker_grant_id=?",
                        (existing["worker_grant_id"],),
                    ).fetchone()
                    return {
                        "worker_grant_id": existing["worker_grant_id"],
                        "request_id": request_id,
                        "grant_hash": existing["grant_hash"],
                        "expires_at": existing["expires_at"],
                        "consumed": consumed is not None,
                        "idempotent": True,
                    }
                now_dt = _utc_now(self.repository.clock); now = _timestamp(self.repository.clock)
                expires_at = (now_dt + timedelta(seconds=ttl_seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                value = {
                    "request_id": request_id,
                    "run_id": row["run_id"],
                    "project_id": row["project_id"],
                    "source_policy_hash": row["source_policy_hash"],
                    "worker_id": worker_id,
                    "worker_session": worker_session,
                    "max_candidates": max_candidates,
                    "max_bytes": max_bytes,
                    "reason_hash": reason_hash,
                    "issued_at": now,
                    "expires_at": expires_at,
                }
                grant_hash = canonical_sha256(value); worker_grant_id = make_stable_id("acquisition_worker_grant", grant_hash[:64])
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                connection.execute(
                    "INSERT INTO max_acquisition_worker_grants(worker_grant_id, request_id, run_id, project_id, source_policy_hash, worker_id, worker_session, max_candidates, max_bytes, reason_hash, issued_at, expires_at, grant_json, grant_hash, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (worker_grant_id, request_id, row["run_id"], row["project_id"], row["source_policy_hash"], worker_id, worker_session, max_candidates, max_bytes, reason_hash, now, expires_at, canonical_json(value), grant_hash, actor_id, actor_kind, actor_session),
                )
                self._event(connection, request_id=request_id, run_id=row["run_id"], project_id=row["project_id"], event_type="worker_authorized", payload={"worker_grant_id": worker_grant_id, "grant_hash": grant_hash, "max_candidates": max_candidates, "max_bytes": max_bytes, "expires_at": expires_at}, actor=actor, now=now)
                self.repository._append_event(connection, run_id=row["run_id"], event_type="acquisition_worker_authorized", payload={"request_id": request_id, "worker_grant_id": worker_grant_id, "grant_hash": grant_hash, "max_candidates": max_candidates, "max_bytes": max_bytes}, actor=actor, now=now)
            return {"worker_grant_id": worker_grant_id, "request_id": request_id, "grant_hash": grant_hash, "expires_at": expires_at, "consumed": False, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("acquisition worker grant conflicted with another administrator") from exc
        finally:
            connection.close()

    def claim(self, *, request_id: str, worker_grant_id: str, actor: Actor) -> dict[str, Any]:
        if actor.is_admin or actor.actor_kind not in {"worker", "agent", "runner"}:
            raise MaxControlError("acquisition claim requires an authorized non-admin worker")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT r.*, c.state FROM max_acquisition_requests r JOIN max_acquisition_current c ON c.request_id=r.request_id WHERE r.request_id=?", (request_id,)).fetchone()
                if row is None:
                    raise MaxControlError("acquisition request was not found")
                existing = connection.execute("SELECT * FROM max_acquisition_claims WHERE request_id=?", (request_id,)).fetchone()
                if existing is not None:
                    if existing["worker_id"] != actor.actor_id or existing["worker_session"] != actor.session_id or existing["worker_grant_id"] != worker_grant_id:
                        raise MaxControlError("acquisition request is already claimed by another worker")
                    return {"claim_id": existing["claim_id"], "request_id": request_id, "state": "claimed", "idempotent": True}
                if row["state"] != "approved":
                    raise MaxControlError("only an approved acquisition request can be claimed")
                grant = connection.execute("SELECT * FROM max_acquisition_worker_grants WHERE worker_grant_id=? AND request_id=?", (worker_grant_id, request_id)).fetchone()
                if grant is None or grant["run_id"] != row["run_id"] or grant["project_id"] != row["project_id"] or grant["source_policy_hash"] != row["source_policy_hash"] or grant["worker_id"] != actor.actor_id or grant["worker_session"] != actor.session_id:
                    raise MaxControlError("acquisition worker grant binding is invalid")
                if _utc_now(self.repository.clock) >= _parse_timestamp(grant["expires_at"]):
                    raise MaxControlError("acquisition worker grant expired")
                now = _timestamp(self.repository.clock)
                consumption_value = {"worker_grant_id": worker_grant_id, "request_id": request_id, "run_id": row["run_id"], "project_id": row["project_id"], "worker_id": actor.actor_id, "worker_session": actor.session_id, "consumed_at": now}
                consumption_hash = canonical_sha256(consumption_value); consumption_id = make_stable_id("acquisition_worker_grant_consumption", consumption_hash[:64])
                connection.execute("INSERT INTO max_acquisition_worker_grant_consumptions(consumption_id, worker_grant_id, request_id, run_id, project_id, worker_id, worker_session, consumed_at, consumption_json, consumption_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (consumption_id, worker_grant_id, request_id, row["run_id"], row["project_id"], actor.actor_id, actor.session_id, now, canonical_json(consumption_value), consumption_hash))
                value = {"request_id": request_id, "run_id": row["run_id"], "worker_grant_id": worker_grant_id, "grant_consumption_id": consumption_id, "worker_id": actor.actor_id, "worker_session": actor.session_id, "claimed_at": now}
                claim_hash = canonical_sha256(value); claim_id = make_stable_id("acquisition_claim", claim_hash[:64])
                connection.execute("INSERT INTO max_acquisition_claims(claim_id, request_id, run_id, worker_grant_id, grant_consumption_id, worker_id, worker_session, claimed_at, claim_json, claim_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (claim_id, request_id, row["run_id"], worker_grant_id, consumption_id, actor.actor_id, actor.session_id, now, canonical_json(value), claim_hash))
                self._set_current(connection, row=row, state="claimed", actor=actor, now=now, payload={"claim_id": claim_id, "claim_hash": claim_hash, "worker_grant_id": worker_grant_id, "grant_consumption_id": consumption_id})
            return {"claim_id": claim_id, "request_id": request_id, "state": "claimed", "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("acquisition claim was concurrently consumed") from exc
        finally:
            connection.close()

    def stage(
        self,
        *,
        request_id: str,
        claim_id: str,
        staging_manifest_hash: str,
        validation_hash: str,
        dry_run_manifest_hash: str,
        candidate_count: int,
        total_bytes: int,
        actor: Actor,
    ) -> dict[str, Any]:
        """Reject the obsolete worker-supplied hash attestation path.

        Retaining this method as an explicit fail-closed compatibility guard is
        safer than silently accepting three caller-provided hashes.  Callers
        must use :meth:`validate_and_stage`.
        """

        del request_id, claim_id, staging_manifest_hash, validation_hash
        del dry_run_manifest_hash, candidate_count, total_bytes, actor
        raise MaxControlError("worker-supplied staging attestations are forbidden; use validate_and_stage")

    def validate_and_stage(
        self,
        *,
        request_id: str,
        claim_id: str,
        staging_run: str | Path,
        actor: Actor,
        existing_content_hashes: set[str] | frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        """Independently validate a staging directory and atomically attest it.

        Validation reads only the explicitly named staging directory and does
        not ingest, copy, OCR, execute, or connect to a network.  The worker
        that produced the directory may not act as its validator.
        """

        if not (actor.is_admin or actor.actor_kind == "validator"):
            raise MaxControlError("acquisition staging requires an independent validator or human admin")
        if not isinstance(existing_content_hashes, (set, frozenset)) or any(not isinstance(value, str) or not _HASH_RE.fullmatch(value.lower()) for value in existing_content_hashes):
            raise MaxControlError("existing content hashes are invalid")

        # Read caps and identity before touching the staging directory.  They
        # are rechecked in the write transaction to close the TOCTOU window on
        # control-plane state (same-account filesystem mutation remains outside
        # the declared threat model, but every file hash is bound in receipt).
        read = self.repository._connect(read_only=True)
        try:
            row = read.execute("SELECT r.*, c.state FROM max_acquisition_requests r JOIN max_acquisition_current c ON c.request_id=r.request_id WHERE r.request_id=?", (request_id,)).fetchone()
            claim = read.execute("SELECT * FROM max_acquisition_claims WHERE claim_id=? AND request_id=?", (claim_id, request_id)).fetchone()
            if row is None or claim is None or row["state"] != "claimed":
                raise MaxControlError("acquisition staging lacks a current worker claim")
            if claim["worker_id"] == actor.actor_id and claim["worker_session"] == actor.session_id:
                raise MaxControlError("an acquisition worker cannot validate its own staging output")
            grant = read.execute("SELECT * FROM max_acquisition_worker_grants WHERE worker_grant_id=?", (claim["worker_grant_id"],)).fetchone()
            consumption = read.execute("SELECT * FROM max_acquisition_worker_grant_consumptions WHERE consumption_id=? AND worker_grant_id=?", (claim["grant_consumption_id"], claim["worker_grant_id"])).fetchone()
            request = AcquisitionRequest.from_mapping(json.loads(row["request_json"]))
            if grant is None or consumption is None:
                raise MaxControlError("acquisition staging lacks its one-shot worker authority")
            max_candidates = min(int(grant["max_candidates"]), int(request.max_candidates))
            max_bytes = int(grant["max_bytes"])
        finally:
            read.close()

        result = validate_staging_run(
            staging_run,
            max_candidates=max_candidates,
            max_total_bytes=max_bytes,
            existing_content_hashes=frozenset(value.lower() for value in existing_content_hashes),
        )
        validation = result["validation"]
        projection = result["dry_run_manifest"]
        validation_hash = _hash(result["validation_hash"], "validation_hash")
        staging_manifest_hash = _hash(validation["staging_manifest_hash"], "staging_manifest_hash")
        output_set_hash = _hash(validation["output_set_hash"], "output_set_hash")
        dry_run_manifest_hash = _hash(validation["dry_run_manifest_hash"], "dry_run_manifest_hash")
        if validation.get("validator_version_hash") != STAGING_VALIDATOR_VERSION_HASH or canonical_sha256(projection) != dry_run_manifest_hash:
            raise MaxControlError("staging validator output failed its authority binding")
        candidate_count = int(validation["document_count"])
        total_bytes = int(validation["total_bytes"])
        eligible_count = int(projection["eligible_count"])
        duplicate_count = int(projection["duplicate_count"])
        manual_review_count = int(projection["manual_review_count"])

        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT r.*, c.state FROM max_acquisition_requests r JOIN max_acquisition_current c ON c.request_id=r.request_id WHERE r.request_id=?", (request_id,)).fetchone()
                claim = connection.execute("SELECT * FROM max_acquisition_claims WHERE claim_id=? AND request_id=?", (claim_id, request_id)).fetchone()
                if row is None or claim is None or row["state"] not in {"claimed", "staged"}:
                    raise MaxControlError("acquisition stage receipt lacks a valid current claim")
                if claim["worker_id"] == actor.actor_id and claim["worker_session"] == actor.session_id:
                    raise MaxControlError("an acquisition worker cannot validate its own staging output")
                request = AcquisitionRequest.from_mapping(json.loads(row["request_json"]))
                grant = connection.execute("SELECT * FROM max_acquisition_worker_grants WHERE worker_grant_id=?", (claim["worker_grant_id"],)).fetchone()
                consumption = connection.execute("SELECT * FROM max_acquisition_worker_grant_consumptions WHERE consumption_id=? AND worker_grant_id=?", (claim["grant_consumption_id"], claim["worker_grant_id"])).fetchone()
                if grant is None or consumption is None or candidate_count > request.max_candidates or candidate_count > int(grant["max_candidates"]) or total_bytes > int(grant["max_bytes"]):
                    raise MaxControlError("acquisition stage exceeds or lacks its worker grant")
                existing_validation = connection.execute("SELECT * FROM max_acquisition_validation_receipts WHERE request_id=?", (request_id,)).fetchone()
                existing = connection.execute("SELECT * FROM max_acquisition_stage_receipts WHERE request_id=?", (request_id,)).fetchone()
                if existing_validation is not None or existing is not None:
                    if existing_validation is None or existing is None:
                        raise MaxControlError("acquisition stage receipt set is incomplete")
                    expected_validation = {"claim_id": claim_id, "worker_grant_id": claim["worker_grant_id"], "staging_manifest_hash": staging_manifest_hash, "output_set_hash": output_set_hash, "validation_hash": validation_hash, "dry_run_manifest_hash": dry_run_manifest_hash, "validator_version_hash": STAGING_VALIDATOR_VERSION_HASH, "candidate_count": candidate_count, "eligible_count": eligible_count, "duplicate_count": duplicate_count, "manual_review_count": manual_review_count, "total_bytes": total_bytes}
                    expected_stage = {"claim_id": claim_id, "validation_receipt_id": existing_validation["validation_receipt_id"], "staging_manifest_hash": staging_manifest_hash, "validation_hash": validation_hash, "dry_run_manifest_hash": dry_run_manifest_hash, "candidate_count": candidate_count, "total_bytes": total_bytes}
                    if any(existing_validation[key] != value for key, value in expected_validation.items()) or any(existing[key] != value for key, value in expected_stage.items()):
                        raise MaxControlError("acquisition stage receipt replay differs")
                    return {"validation_receipt_id": existing_validation["validation_receipt_id"], "receipt_id": existing["receipt_id"], "request_id": request_id, "state": "staged", "validation_hash": validation_hash, "dry_run_manifest_hash": dry_run_manifest_hash, "candidate_count": candidate_count, "eligible_count": eligible_count, "duplicate_count": duplicate_count, "manual_review_count": manual_review_count, "idempotent": True}
                now = _timestamp(self.repository.clock)
                validation_value = {"request_id": request_id, "claim_id": claim_id, "run_id": row["run_id"], "project_id": row["project_id"], "worker_grant_id": claim["worker_grant_id"], "staging_manifest_hash": staging_manifest_hash, "output_set_hash": output_set_hash, "validation_hash": validation_hash, "dry_run_manifest_hash": dry_run_manifest_hash, "validator_version_hash": STAGING_VALIDATOR_VERSION_HASH, "candidate_count": candidate_count, "eligible_count": eligible_count, "duplicate_count": duplicate_count, "manual_review_count": manual_review_count, "total_bytes": total_bytes, "created_at": now}
                validation_receipt_hash = canonical_sha256(validation_value); validation_receipt_id = make_stable_id("acquisition_validation_receipt", validation_receipt_hash[:64])
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                connection.execute("INSERT INTO max_acquisition_validation_receipts(validation_receipt_id, request_id, claim_id, run_id, project_id, worker_grant_id, staging_manifest_hash, output_set_hash, validation_hash, dry_run_manifest_hash, validator_version_hash, candidate_count, eligible_count, duplicate_count, manual_review_count, total_bytes, receipt_json, receipt_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (validation_receipt_id, request_id, claim_id, row["run_id"], row["project_id"], claim["worker_grant_id"], staging_manifest_hash, output_set_hash, validation_hash, dry_run_manifest_hash, STAGING_VALIDATOR_VERSION_HASH, candidate_count, eligible_count, duplicate_count, manual_review_count, total_bytes, canonical_json(validation_value), validation_receipt_hash, now, actor_id, actor_kind, actor_session))
                value = {"request_id": request_id, "claim_id": claim_id, "validation_receipt_id": validation_receipt_id, "run_id": row["run_id"], "project_id": row["project_id"], "staging_manifest_hash": staging_manifest_hash, "validation_hash": validation_hash, "dry_run_manifest_hash": dry_run_manifest_hash, "candidate_count": candidate_count, "total_bytes": total_bytes, "created_at": now}
                receipt_hash = canonical_sha256(value); receipt_id = make_stable_id("acquisition_stage_receipt", receipt_hash[:64])
                connection.execute("INSERT INTO max_acquisition_stage_receipts(receipt_id, request_id, claim_id, validation_receipt_id, run_id, project_id, staging_manifest_hash, validation_hash, dry_run_manifest_hash, candidate_count, total_bytes, receipt_json, receipt_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (receipt_id, request_id, claim_id, validation_receipt_id, row["run_id"], row["project_id"], staging_manifest_hash, validation_hash, dry_run_manifest_hash, candidate_count, total_bytes, canonical_json(value), receipt_hash, now, actor_id, actor_kind, actor_session))
                self._set_current(connection, row=row, state="staged", actor=actor, now=now, payload={"validation_receipt_id": validation_receipt_id, "validation_receipt_hash": validation_receipt_hash, "receipt_id": receipt_id, "receipt_hash": receipt_hash, "staging_manifest_hash": staging_manifest_hash, "validation_hash": validation_hash, "dry_run_manifest_hash": dry_run_manifest_hash, "candidate_count": candidate_count, "eligible_count": eligible_count, "duplicate_count": duplicate_count, "manual_review_count": manual_review_count, "total_bytes": total_bytes})
            return {"validation_receipt_id": validation_receipt_id, "receipt_id": receipt_id, "request_id": request_id, "state": "staged", "validation_hash": validation_hash, "dry_run_manifest_hash": dry_run_manifest_hash, "candidate_count": candidate_count, "eligible_count": eligible_count, "duplicate_count": duplicate_count, "manual_review_count": manual_review_count, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("acquisition validation conflicted with immutable history") from exc
        finally:
            connection.close()

    def status(self, *, run_id: str, request_id: str | None = None) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            rows = list(connection.execute("SELECT r.*, c.state, c.current_json, c.current_hash, c.updated_at FROM max_acquisition_requests r JOIN max_acquisition_current c ON c.request_id=r.request_id WHERE r.run_id=?" + (" AND r.request_id=?" if request_id is not None else "") + " ORDER BY r.created_at, r.request_id", ((run_id, request_id) if request_id is not None else (run_id,))))
            values = []
            for row in rows:
                current = json.loads(row["current_json"]); expected = self._current_value(request_id=row["request_id"], run_id=row["run_id"], project_id=row["project_id"], state=row["state"])
                if current != expected or canonical_sha256(current) != row["current_hash"]:
                    raise MaxControlError("acquisition current projection is invalid")
                request = AcquisitionRequest.from_mapping(json.loads(row["request_json"]))
                values.append({"request_id": row["request_id"], "request_hash": row["request_hash"], "run_id": row["run_id"], "project_id": row["project_id"], "state": row["state"], "research_gap": request.research_gap, "desired_source_role": request.desired_source_role, "max_candidates": request.max_candidates, "updated_at": row["updated_at"]})
            return {"run_id": run_id, "requests": values, "count": len(values)}
        finally:
            connection.close()

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        issues: list[str] = []
        counts = {"requests": 0, "worker_grants": 0, "grant_consumptions": 0, "claims": 0, "validation_receipts": 0, "stage_receipts": 0, "events": 0}
        connection = self.repository._connect(read_only=True)
        try:
            rows = list(connection.execute("SELECT r.*, c.state, c.current_json, c.current_hash FROM max_acquisition_requests r JOIN max_acquisition_current c ON c.request_id=r.request_id" + (" WHERE r.run_id=?" if run_id is not None else ""), ((run_id,) if run_id is not None else ())))
            for row in rows:
                counts["requests"] += 1
                try:
                    request = AcquisitionRequest.from_mapping(json.loads(row["request_json"])); validate_acquisition_request(request).raise_if_invalid()
                    current = json.loads(row["current_json"]); expected = self._current_value(request_id=row["request_id"], run_id=row["run_id"], project_id=row["project_id"], state=row["state"])
                    run = connection.execute("SELECT source_policy_hash FROM max_runs WHERE run_id=? AND project_id=?", (row["run_id"], row["project_id"])).fetchone()
                    if canonical_sha256(model_to_dict(request)) != row["request_hash"] or current != expected or canonical_sha256(current) != row["current_hash"] or run is None or run["source_policy_hash"] != row["source_policy_hash"]:
                        issues.append("acquisition request/current binding mismatch")
                except Exception:
                    issues.append("acquisition request is invalid")
                grants = list(connection.execute("SELECT * FROM max_acquisition_worker_grants WHERE request_id=?", (row["request_id"],)))
                consumptions = list(connection.execute("SELECT * FROM max_acquisition_worker_grant_consumptions WHERE request_id=?", (row["request_id"],)))
                claims = list(connection.execute("SELECT * FROM max_acquisition_claims WHERE request_id=?", (row["request_id"],)))
                validations = list(connection.execute("SELECT * FROM max_acquisition_validation_receipts WHERE request_id=?", (row["request_id"],)))
                stages = list(connection.execute("SELECT * FROM max_acquisition_stage_receipts WHERE request_id=?", (row["request_id"],)))
                for name, items in (("worker_grants", grants), ("grant_consumptions", consumptions), ("claims", claims), ("validation_receipts", validations), ("stage_receipts", stages)):
                    counts[name] += len(items)
                    if len(items) > 1:
                        issues.append(f"acquisition {name} cardinality mismatch")

                try:
                    if grants:
                        item = grants[0]
                        value = {"request_id": item["request_id"], "run_id": item["run_id"], "project_id": item["project_id"], "source_policy_hash": item["source_policy_hash"], "worker_id": item["worker_id"], "worker_session": item["worker_session"], "max_candidates": int(item["max_candidates"]), "max_bytes": int(item["max_bytes"]), "reason_hash": item["reason_hash"], "issued_at": item["issued_at"], "expires_at": item["expires_at"]}
                        if json.loads(item["grant_json"]) != value or canonical_sha256(value) != item["grant_hash"] or item["run_id"] != row["run_id"] or item["project_id"] != row["project_id"] or item["source_policy_hash"] != row["source_policy_hash"]:
                            issues.append("acquisition worker grant binding mismatch")
                    if consumptions:
                        item = consumptions[0]
                        value = {"worker_grant_id": item["worker_grant_id"], "request_id": item["request_id"], "run_id": item["run_id"], "project_id": item["project_id"], "worker_id": item["worker_id"], "worker_session": item["worker_session"], "consumed_at": item["consumed_at"]}
                        if not grants or item["worker_grant_id"] != grants[0]["worker_grant_id"] or json.loads(item["consumption_json"]) != value or canonical_sha256(value) != item["consumption_hash"]:
                            issues.append("acquisition worker grant consumption binding mismatch")
                    if claims:
                        item = claims[0]
                        value = {"request_id": item["request_id"], "run_id": item["run_id"], "worker_grant_id": item["worker_grant_id"], "grant_consumption_id": item["grant_consumption_id"], "worker_id": item["worker_id"], "worker_session": item["worker_session"], "claimed_at": item["claimed_at"]}
                        if not grants or not consumptions or item["worker_grant_id"] != grants[0]["worker_grant_id"] or item["grant_consumption_id"] != consumptions[0]["consumption_id"] or json.loads(item["claim_json"]) != value or canonical_sha256(value) != item["claim_hash"]:
                            issues.append("acquisition claim authority binding mismatch")
                    if validations:
                        item = validations[0]
                        value = {"request_id": item["request_id"], "claim_id": item["claim_id"], "run_id": item["run_id"], "project_id": item["project_id"], "worker_grant_id": item["worker_grant_id"], "staging_manifest_hash": item["staging_manifest_hash"], "output_set_hash": item["output_set_hash"], "validation_hash": item["validation_hash"], "dry_run_manifest_hash": item["dry_run_manifest_hash"], "validator_version_hash": item["validator_version_hash"], "candidate_count": int(item["candidate_count"]), "eligible_count": int(item["eligible_count"]), "duplicate_count": int(item["duplicate_count"]), "manual_review_count": int(item["manual_review_count"]), "total_bytes": int(item["total_bytes"]), "created_at": item["created_at"]}
                        if not claims or not grants or item["claim_id"] != claims[0]["claim_id"] or item["worker_grant_id"] != grants[0]["worker_grant_id"] or item["validator_version_hash"] != STAGING_VALIDATOR_VERSION_HASH or item["actor_kind"] not in {"user", "validator"} or (item["actor_id"] == claims[0]["worker_id"] and item["actor_session"] == claims[0]["worker_session"]) or json.loads(item["receipt_json"]) != value or canonical_sha256(value) != item["receipt_hash"]:
                            issues.append("acquisition validation receipt authority binding mismatch")
                    if stages:
                        item = stages[0]
                        value = {"request_id": item["request_id"], "claim_id": item["claim_id"], "validation_receipt_id": item["validation_receipt_id"], "run_id": item["run_id"], "project_id": item["project_id"], "staging_manifest_hash": item["staging_manifest_hash"], "validation_hash": item["validation_hash"], "dry_run_manifest_hash": item["dry_run_manifest_hash"], "candidate_count": int(item["candidate_count"]), "total_bytes": int(item["total_bytes"]), "created_at": item["created_at"]}
                        validation = validations[0] if validations else None
                        if validation is None or item["validation_receipt_id"] != validation["validation_receipt_id"] or item["claim_id"] != validation["claim_id"] or any(item[key] != validation[key] for key in ("staging_manifest_hash", "validation_hash", "dry_run_manifest_hash", "candidate_count", "total_bytes")) or json.loads(item["receipt_json"]) != value or canonical_sha256(value) != item["receipt_hash"]:
                            issues.append("acquisition stage/validation receipt binding mismatch")
                except Exception:
                    issues.append("acquisition authority record is invalid")

                expected_counts = {
                    "proposed": (0, 0, 0, 0, 0),
                    "approved": (None, 0, 0, 0, 0),
                    "claimed": (1, 1, 1, 0, 0),
                    "staged": (1, 1, 1, 1, 1),
                    "accepted": (1, 1, 1, 1, 1),
                    "cancelled": (None, 0, 0, 0, 0),
                }
                if row["state"] in expected_counts:
                    actual = (len(grants), len(consumptions), len(claims), len(validations), len(stages))
                    expected = expected_counts[row["state"]]
                    if any(want is not None and got != want for got, want in zip(actual, expected)):
                        issues.append("acquisition state/authority cardinality mismatch")
                elif row["state"] == "rejected":
                    actual = (len(grants), len(consumptions), len(claims), len(validations), len(stages))
                    allowed_rejected = {
                        (0, 0, 0, 0, 0),
                        (1, 0, 0, 0, 0),
                        (1, 1, 1, 0, 0),
                        (1, 1, 1, 1, 1),
                    }
                    if actual not in allowed_rejected:
                        issues.append("rejected acquisition has an impossible authority history")
                events = list(connection.execute("SELECT * FROM max_acquisition_events WHERE request_id=? ORDER BY sequence_no", (row["request_id"],))); counts["events"] += len(events); previous = None
                for sequence, event in enumerate(events, 1):
                    try:
                        payload = json.loads(event["payload_json"]); value = {"request_id": event["request_id"], "run_id": event["run_id"], "project_id": event["project_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if int(event["sequence_no"]) != sequence or canonical_sha256(payload) != event["payload_hash"] or event["previous_event_hash"] != previous or canonical_sha256(value) != event["event_hash"]: issues.append("acquisition event chain mismatch")
                        previous = event["event_hash"]
                    except Exception: issues.append("acquisition event is invalid")
                state_events = [event for event in events if event["event_type"] in {"proposed", "approved", "claimed", "staged", "accepted", "rejected", "cancelled"}]
                if state_events and state_events[-1]["event_type"] != row["state"]: issues.append("acquisition current state differs from event tip")
                if row["state"] == "accepted" and stages:
                    try:
                        payload = json.loads(state_events[-1]["payload_json"])
                        stage = stages[0]
                        if any(payload.get(key) != stage[key] for key in ("receipt_id", "receipt_hash", "validation_hash", "dry_run_manifest_hash")):
                            issues.append("accepted acquisition differs from staged receipt")
                    except Exception:
                        issues.append("accepted acquisition event is invalid")
            return {"ok": not issues, "run_id": run_id, "counts": counts, "issues": sorted(set(issues))}
        finally:
            connection.close()


__all__ = ["AcquisitionControl"]
