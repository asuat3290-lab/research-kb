"""MR-2B2 controlled live-runner entry point.

This module is the only production control-plane path that may construct the
real HTTPS transport factory.  Importing it performs no network, DNS, or
credential work.  Execution additionally requires a run-bound confirmation
hash, a durable authorization bundle, a consumed execution grant, and the
current fenced runner handoff.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from typing import Any, Mapping

from ...policy import Actor
from ..contract import canonical_json, canonical_sha256, make_stable_id
from ..persistence.db import MaxControlError, control_transaction
from ..persistence.repository import MaxControlRepository, _actor_fields, _parse_timestamp, _timestamp, _utc_now
from ..persistence.runner import RunnerPersistence
from ..runner import BoundedRunner, RunnerProfile
from .bundle import LiveAuthorizationBundleStore, LiveAuthorizationPoolAdapter
from .contract import ProviderProfile
from .live import LiveProviderTransportFactory
from .store import ProviderStore
from .usage import ProviderUsageAuthority


LIVE_EXECUTION_ACK = "I_APPROVE_ONE_BOUNDED_LIVE_MAX_ITERATION"


def live_execution_confirmation_hash(*, run_id: str, grant_id: str, bundle_id: str, profile_hash: str, runner_profile_hash: str) -> str:
    """Return a non-authoritative preview hash for an execution set.

    Human authority is the durable :class:`LiveIterationApprovalStore` record,
    not this publicly computable digest.
    """

    return canonical_sha256({
        "ack": LIVE_EXECUTION_ACK,
        "run_id": run_id,
        "grant_id": grant_id,
        "bundle_id": bundle_id,
        "profile_hash": profile_hash,
        "runner_profile_hash": runner_profile_hash,
    })


class LiveIterationApprovalStore:
    """Issue and consume one human approval for exactly one live iteration."""

    def __init__(self, repository: MaxControlRepository) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("LiveIterationApprovalStore requires MaxControlRepository")
        self.repository = repository

    def issue(self, *, run_id: str, grant_id: str, bundle_id: str, provider_profile_hash: str, runner_profile_hash: str, reason: str, actor: Actor, ttl_seconds: int = 900) -> dict[str, Any]:
        if not actor.is_admin:
            raise MaxControlError("live iteration approval requires human admin authority")
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 2_000 or "\r" in reason or "\n" in reason:
            raise MaxControlError("live iteration approval reason is invalid")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 3_600:
            raise MaxControlError("live iteration approval TTL is invalid")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                bundle = connection.execute("SELECT * FROM max_live_authorization_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
                bundle_current = connection.execute("SELECT * FROM max_live_authorization_bundle_current WHERE bundle_id=?", (bundle_id,)).fetchone()
                profile = connection.execute("SELECT profile_hash FROM max_provider_profiles WHERE profile_hash=?", (provider_profile_hash,)).fetchone()
                runner_profile = connection.execute("SELECT profile_hash FROM max_runner_profiles WHERE profile_hash=?", (runner_profile_hash,)).fetchone()
                lease = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if any(item is None for item in (run, grant, bundle, bundle_current, profile, runner_profile, lease)):
                    raise MaxControlError("live iteration approval binding is incomplete")
                now_dt = _utc_now(self.repository.clock)
                if run["status"] != "RUNNING" or not run["current_state_hash"] or bundle_current["state"] != "active" or _parse_timestamp(bundle["expires_at"]) is None or _parse_timestamp(bundle["expires_at"]) <= now_dt:
                    raise MaxControlError("live iteration approval run or bundle is not eligible")
                expected = {"run_id": run_id, "project_id": run["project_id"], "grant_id": grant_id, "profile_hash": provider_profile_hash, "model_identity": run["model_identity"], "budget_hash": run["budget_hash"]}
                if any(bundle[key] != value for key, value in expected.items()) or any(grant[key] != value for key, value in {"run_id": run_id, "project_id": run["project_id"], "profile_hash": provider_profile_hash, "model_identity": run["model_identity"], "budget_hash": run["budget_hash"]}.items()):
                    raise MaxControlError("live iteration approval provider authority binding mismatch")
                if lease["runner_profile_hash"] != runner_profile_hash or not lease["owner_id"] or not lease["session_id"] or lease["released_at"] is not None or _parse_timestamp(lease["expires_at"]) is None or _parse_timestamp(lease["expires_at"]) <= now_dt:
                    raise MaxControlError("live iteration approval runner handoff is invalid")
                if connection.execute("SELECT 1 FROM max_iteration_current WHERE run_id=?", (run_id,)).fetchone() is not None:
                    raise MaxControlError("live iteration approval cannot be issued while an iteration is in flight")
                expected_sequence = int(connection.execute("SELECT COALESCE(MAX(sequence_no),0)+1 FROM max_iterations WHERE run_id=?", (run_id,)).fetchone()[0])
                if connection.execute("SELECT 1 FROM max_live_iteration_approval_consumptions WHERE run_id=? AND expected_sequence=?", (run_id, expected_sequence)).fetchone() is not None:
                    raise MaxControlError("the next live iteration already consumed human approval")
                now = _timestamp(self.repository.clock)
                expires_at = (now_dt + timedelta(seconds=ttl_seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                reason_hash = canonical_sha256(reason.strip())
                active = connection.execute(
                    "SELECT * FROM max_live_iteration_approvals WHERE run_id=? AND expected_sequence=? AND expires_at>? "
                    "AND NOT EXISTS (SELECT 1 FROM max_live_iteration_approval_consumptions c WHERE c.live_iteration_approval_id=max_live_iteration_approvals.live_iteration_approval_id) "
                    "ORDER BY created_at DESC LIMIT 1",
                    (run_id, expected_sequence, now),
                ).fetchone()
                if active is not None:
                    semantic = {
                        "current_state_hash": run["current_state_hash"],
                        "grant_id": grant_id,
                        "bundle_id": bundle_id,
                        "provider_profile_hash": provider_profile_hash,
                        "runner_profile_hash": runner_profile_hash,
                        "runner_id": lease["owner_id"],
                        "runner_session": lease["session_id"],
                        "fencing_token": int(lease["fencing_token"]),
                        "reason_hash": reason_hash,
                    }
                    if any(active[key] != value for key, value in semantic.items()):
                        raise MaxControlError("an active approval already owns the next live iteration")
                    return {
                        "live_iteration_approval_id": active["live_iteration_approval_id"],
                        "approval_hash": active["approval_hash"],
                        "run_id": run_id,
                        "expected_sequence": expected_sequence,
                        "expires_at": active["expires_at"],
                        "consumed": False,
                        "idempotent": True,
                    }
                value = {"run_id": run_id, "project_id": run["project_id"], "expected_sequence": expected_sequence, "current_state_hash": run["current_state_hash"], "grant_id": grant_id, "bundle_id": bundle_id, "provider_profile_hash": provider_profile_hash, "runner_profile_hash": runner_profile_hash, "runner_id": lease["owner_id"], "runner_session": lease["session_id"], "fencing_token": int(lease["fencing_token"]), "reason_hash": reason_hash, "expires_at": expires_at, "created_at": now}
                approval_hash = canonical_sha256(value)
                approval_id = make_stable_id("live_iteration_approval", approval_hash[:64])
                existing = connection.execute("SELECT * FROM max_live_iteration_approvals WHERE live_iteration_approval_id=?", (approval_id,)).fetchone()
                if existing is not None:
                    if existing["approval_hash"] != approval_hash or json.loads(existing["approval_json"]) != value:
                        raise MaxControlError("live iteration approval ID collision")
                    return {"live_iteration_approval_id": approval_id, "approval_hash": approval_hash, "run_id": run_id, "expected_sequence": expected_sequence, "expires_at": expires_at, "consumed": False, "idempotent": True}
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                connection.execute("INSERT INTO max_live_iteration_approvals(live_iteration_approval_id, run_id, project_id, expected_sequence, current_state_hash, grant_id, bundle_id, provider_profile_hash, runner_profile_hash, runner_id, runner_session, fencing_token, reason_hash, expires_at, approval_json, approval_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (approval_id, run_id, run["project_id"], expected_sequence, run["current_state_hash"], grant_id, bundle_id, provider_profile_hash, runner_profile_hash, lease["owner_id"], lease["session_id"], int(lease["fencing_token"]), value["reason_hash"], expires_at, canonical_json(value), approval_hash, now, actor_id, actor_kind, actor_session))
                self.repository._append_event(connection, run_id=run_id, event_type="live_iteration_approval_issued", payload={"live_iteration_approval_id": approval_id, "approval_hash": approval_hash, "expected_sequence": expected_sequence, "grant_id": grant_id, "bundle_id": bundle_id, "runner_profile_hash": runner_profile_hash, "expires_at": expires_at}, actor=actor, now=now)
            return {"live_iteration_approval_id": approval_id, "approval_hash": approval_hash, "run_id": run_id, "expected_sequence": expected_sequence, "expires_at": expires_at, "consumed": False, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live iteration approval conflicts with immutable authority") from exc
        finally:
            connection.close()

    def consume(self, *, live_iteration_approval_id: str, run_id: str, grant_id: str, bundle_id: str, provider_profile_hash: str, runner_profile_hash: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        if actor.is_admin or actor.actor_kind not in {"runner", "worker", "agent"}:
            raise MaxControlError("live iteration approval consumption requires its runner")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                approval = connection.execute("SELECT * FROM max_live_iteration_approvals WHERE live_iteration_approval_id=?", (live_iteration_approval_id,)).fetchone()
                if approval is None:
                    raise MaxControlError("live iteration approval was not found")
                expected = {"run_id": run_id, "grant_id": grant_id, "bundle_id": bundle_id, "provider_profile_hash": provider_profile_hash, "runner_profile_hash": runner_profile_hash, "runner_id": actor.actor_id, "runner_session": actor.session_id, "fencing_token": fencing_token}
                if any(approval[key] != value for key, value in expected.items()):
                    raise MaxControlError("live iteration approval binding mismatch")
                now_dt = _utc_now(self.repository.clock)
                run = connection.execute("SELECT project_id, status, current_state_hash FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                lease = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if run is None or run["status"] != "RUNNING" or run["project_id"] != approval["project_id"]:
                    raise MaxControlError("live iteration approval state binding drifted")
                if lease is None or lease["owner_id"] != actor.actor_id or lease["session_id"] != actor.session_id or int(lease["fencing_token"]) != fencing_token or lease["released_at"] is not None:
                    raise MaxControlError("live iteration approval uses a stale runner fence")
                begun = connection.execute("SELECT iteration_id, sequence_no, input_state_hash FROM max_iterations WHERE run_id=? ORDER BY sequence_no DESC LIMIT 1", (run_id,)).fetchone()
                latest_sequence = int(begun["sequence_no"]) if begun is not None else 0
                expected_sequence = int(approval["expected_sequence"])
                existing = connection.execute("SELECT * FROM max_live_iteration_approval_consumptions WHERE live_iteration_approval_id=?", (live_iteration_approval_id,)).fetchone()
                if existing is not None:
                    outcome = None if begun is None else connection.execute(
                        "SELECT 1 FROM max_iteration_outcomes WHERE iteration_id=?", (begun["iteration_id"],)
                    ).fetchone()
                    open_pointer = connection.execute(
                        "SELECT iteration_id FROM max_iteration_current WHERE run_id=?", (run_id,)
                    ).fetchone()
                    recoverable = (
                        latest_sequence == expected_sequence - 1
                        and run["current_state_hash"] == approval["current_state_hash"]
                    ) or (
                        latest_sequence == expected_sequence
                        and begun is not None
                        and begun["input_state_hash"] == approval["current_state_hash"]
                        and outcome is None
                        and open_pointer is not None
                        and open_pointer["iteration_id"] == begun["iteration_id"]
                    )
                    if any(existing[key] != value for key, value in {"run_id": run_id, "expected_sequence": expected_sequence, "runner_id": actor.actor_id, "runner_session": actor.session_id, "fencing_token": fencing_token}.items()) or not recoverable:
                        raise MaxControlError("live iteration approval replay is not the same recoverable iteration")
                    return {"consumption_id": existing["consumption_id"], "live_iteration_approval_id": live_iteration_approval_id, "expected_sequence": expected_sequence, "idempotent": True}
                if _parse_timestamp(approval["expires_at"]) is None or _parse_timestamp(approval["expires_at"]) <= now_dt:
                    raise MaxControlError("live iteration approval expired")
                if run["current_state_hash"] != approval["current_state_hash"]:
                    raise MaxControlError("live iteration approval state binding drifted")
                if latest_sequence != expected_sequence - 1:
                    raise MaxControlError("live iteration approval does not authorize the next sequence")
                now = _timestamp(self.repository.clock)
                value = {"live_iteration_approval_id": live_iteration_approval_id, "run_id": run_id, "project_id": approval["project_id"], "expected_sequence": expected_sequence, "runner_id": actor.actor_id, "runner_session": actor.session_id, "fencing_token": fencing_token, "consumed_at": now}
                consumption_hash = canonical_sha256(value); consumption_id = make_stable_id("live_iteration_approval_consumption", consumption_hash[:64])
                connection.execute("INSERT INTO max_live_iteration_approval_consumptions(consumption_id, live_iteration_approval_id, run_id, project_id, expected_sequence, runner_id, runner_session, fencing_token, consumed_at, consumption_json, consumption_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (consumption_id, live_iteration_approval_id, run_id, approval["project_id"], expected_sequence, actor.actor_id, actor.session_id, fencing_token, now, canonical_json(value), consumption_hash))
                self.repository._append_event(connection, run_id=run_id, event_type="live_iteration_approval_consumed", payload={"live_iteration_approval_id": live_iteration_approval_id, "consumption_id": consumption_id, "expected_sequence": expected_sequence, "fencing_token": fencing_token}, actor=actor, now=now)
            return {"consumption_id": consumption_id, "live_iteration_approval_id": live_iteration_approval_id, "expected_sequence": expected_sequence, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live iteration approval was concurrently consumed") from exc
        finally:
            connection.close()

    def status(self, *, run_id: str) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            values = []
            for row in connection.execute("SELECT * FROM max_live_iteration_approvals WHERE run_id=? ORDER BY expected_sequence, created_at", (run_id,)):
                consumption = connection.execute("SELECT consumption_id, consumed_at FROM max_live_iteration_approval_consumptions WHERE live_iteration_approval_id=?", (row["live_iteration_approval_id"],)).fetchone()
                values.append({"live_iteration_approval_id": row["live_iteration_approval_id"], "approval_hash": row["approval_hash"], "expected_sequence": int(row["expected_sequence"]), "grant_id": row["grant_id"], "bundle_id": row["bundle_id"], "provider_profile_hash": row["provider_profile_hash"], "runner_profile_hash": row["runner_profile_hash"], "expires_at": row["expires_at"], "consumption": None if consumption is None else {"consumption_id": consumption["consumption_id"], "consumed_at": consumption["consumed_at"]}})
            return {"run_id": run_id, "approvals": values, "count": len(values)}
        finally:
            connection.close()

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        """Recompute every durable one-iteration approval and consumption.

        A consumed approval may legitimately outlive the lease that was
        current when it was issued, so verification binds it to immutable run,
        provider, bundle, profile and iteration history rather than to today's
        lease projection.
        """

        issues: list[str] = []
        counts = {"approvals": 0, "consumptions": 0}
        connection = self.repository._connect(read_only=True)
        try:
            where = " WHERE a.run_id=?" if run_id is not None else ""
            parameters = (run_id,) if run_id is not None else ()
            rows = list(connection.execute(
                "SELECT a.* FROM max_live_iteration_approvals a" + where
                + " ORDER BY a.run_id, a.expected_sequence, a.created_at, a.live_iteration_approval_id",
                parameters,
            ))
            for row in rows:
                counts["approvals"] += 1
                try:
                    value = json.loads(row["approval_json"])
                    expected = {
                        "run_id": row["run_id"],
                        "project_id": row["project_id"],
                        "expected_sequence": int(row["expected_sequence"]),
                        "current_state_hash": row["current_state_hash"],
                        "grant_id": row["grant_id"],
                        "bundle_id": row["bundle_id"],
                        "provider_profile_hash": row["provider_profile_hash"],
                        "runner_profile_hash": row["runner_profile_hash"],
                        "runner_id": row["runner_id"],
                        "runner_session": row["runner_session"],
                        "fencing_token": int(row["fencing_token"]),
                        "reason_hash": row["reason_hash"],
                        "expires_at": row["expires_at"],
                        "created_at": row["created_at"],
                    }
                    if value != expected or canonical_sha256(value) != row["approval_hash"]:
                        issues.append("live iteration approval hash mismatch")
                    authority = connection.execute(
                        "SELECT r.project_id, r.model_identity, r.budget_hash, "
                        "g.profile_hash AS grant_profile, g.model_identity AS grant_model, g.budget_hash AS grant_budget, "
                        "b.grant_id AS bundle_grant, b.profile_hash AS bundle_profile, b.model_identity AS bundle_model, b.budget_hash AS bundle_budget, "
                        "p.profile_hash AS provider_profile, rp.profile_hash AS runner_profile "
                        "FROM max_runs r "
                        "JOIN max_live_execution_grants g ON g.grant_id=? "
                        "JOIN max_live_authorization_bundles b ON b.bundle_id=? "
                        "LEFT JOIN max_provider_profiles p ON p.profile_hash=? "
                        "LEFT JOIN max_runner_profiles rp ON rp.profile_hash=? "
                        "WHERE r.run_id=?",
                        (row["grant_id"], row["bundle_id"], row["provider_profile_hash"], row["runner_profile_hash"], row["run_id"]),
                    ).fetchone()
                    if authority is None or any((
                        authority["project_id"] != row["project_id"],
                        authority["grant_profile"] != row["provider_profile_hash"],
                        authority["bundle_profile"] != row["provider_profile_hash"],
                        authority["bundle_grant"] != row["grant_id"],
                        authority["grant_model"] != authority["model_identity"],
                        authority["bundle_model"] != authority["model_identity"],
                        authority["grant_budget"] != authority["budget_hash"],
                        authority["bundle_budget"] != authority["budget_hash"],
                        authority["provider_profile"] is None,
                        authority["runner_profile"] is None,
                    )):
                        issues.append("live iteration approval authority binding mismatch")
                    iteration = connection.execute(
                        "SELECT input_state_hash FROM max_iterations WHERE run_id=? AND sequence_no=?",
                        (row["run_id"], int(row["expected_sequence"])),
                    ).fetchone()
                    consumption = connection.execute(
                        "SELECT * FROM max_live_iteration_approval_consumptions WHERE live_iteration_approval_id=?",
                        (row["live_iteration_approval_id"],),
                    ).fetchone()
                    if consumption is not None:
                        counts["consumptions"] += 1
                        consumed = json.loads(consumption["consumption_json"])
                        expected_consumption = {
                            "live_iteration_approval_id": consumption["live_iteration_approval_id"],
                            "run_id": consumption["run_id"],
                            "project_id": consumption["project_id"],
                            "expected_sequence": int(consumption["expected_sequence"]),
                            "runner_id": consumption["runner_id"],
                            "runner_session": consumption["runner_session"],
                            "fencing_token": int(consumption["fencing_token"]),
                            "consumed_at": consumption["consumed_at"],
                        }
                        if consumed != expected_consumption or canonical_sha256(consumed) != consumption["consumption_hash"]:
                            issues.append("live iteration approval consumption hash mismatch")
                        for key in ("run_id", "project_id", "expected_sequence", "runner_id", "runner_session", "fencing_token"):
                            if consumption[key] != row[key]:
                                issues.append("live iteration approval consumption binding mismatch")
                                break
                        if iteration is None or iteration["input_state_hash"] != row["current_state_hash"]:
                            issues.append("consumed live iteration approval lacks its exact iteration binding")
                except Exception:
                    issues.append("live iteration approval record is invalid")
            duplicate = connection.execute(
                "SELECT run_id, expected_sequence, COUNT(*) AS count "
                "FROM max_live_iteration_approvals a "
                "WHERE a.expires_at>? AND NOT EXISTS (SELECT 1 FROM max_live_iteration_approval_consumptions c "
                "WHERE c.live_iteration_approval_id=a.live_iteration_approval_id) "
                + ("AND a.run_id=? " if run_id is not None else "")
                + "GROUP BY run_id, expected_sequence HAVING COUNT(*)>1",
                (_timestamp(self.repository.clock), *parameters),
            ).fetchone()
            if duplicate is not None:
                issues.append("multiple unconsumed approvals target one live iteration")
            return {"ok": not issues, "run_id": run_id, "counts": counts, "issues": sorted(set(issues))}
        finally:
            connection.close()


class LiveRunnerExecutor:
    """Advance at most one bounded iteration using the production factory."""

    def __init__(self, repository: MaxControlRepository, actor: Actor, *, provider_store: ProviderStore | None = None, transport_factory: LiveProviderTransportFactory | None = None, usage_authority: ProviderUsageAuthority | None = None) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("LiveRunnerExecutor requires MaxControlRepository")
        if actor.is_admin or actor.actor_kind not in {"runner", "worker", "agent"}:
            raise MaxControlError("live runner execution requires a non-admin runner actor")
        self.repository = repository
        self.actor = actor
        self.provider_store = provider_store or ProviderStore(repository)
        self.bundle_store = LiveAuthorizationBundleStore(self.provider_store)
        self.transport_factory = transport_factory or LiveProviderTransportFactory()
        if type(self.transport_factory) is not LiveProviderTransportFactory:
            if not (repository.is_fixture_database() and isinstance(self.transport_factory, LiveProviderTransportFactory) and getattr(self.transport_factory, "fixture_only", False) is True):
                raise MaxControlError("live runner production transport factory is invalid")
        self.usage_authority = usage_authority or ProviderUsageAuthority()

    def run_next(
        self,
        *,
        run_id: str,
        grant_id: str,
        bundle_id: str,
        provider_profile: ProviderProfile | Mapping[str, Any],
        runner_profile: RunnerProfile | Mapping[str, Any],
        gateway: Any,
        execute_live: bool,
        confirmation_hash: str,
        live_iteration_approval_id: str,
        lease_ttl: int = 300,
    ) -> dict[str, Any]:
        provider = provider_profile if isinstance(provider_profile, ProviderProfile) else ProviderProfile.from_mapping(provider_profile)
        runner = runner_profile if isinstance(runner_profile, RunnerProfile) else RunnerProfile.from_mapping(runner_profile)
        if execute_live is not True:
            raise MaxControlError("live runner execution requires explicit --execute-live authority")
        expected_confirmation = live_execution_confirmation_hash(
            run_id=run_id,
            grant_id=grant_id,
            bundle_id=bundle_id,
            profile_hash=provider.profile_hash,
            runner_profile_hash=runner.profile_hash,
        )
        if confirmation_hash != expected_confirmation:
            raise MaxControlError("live runner execution confirmation binding mismatch")
        if gateway is None or getattr(gateway, "fixture_only", False):
            raise MaxControlError("live runner requires a non-fixture bounded research gateway")
        if runner.model_identity != provider.model_identity:
            raise MaxControlError("live runner/provider model identity mismatch")
        binding = self.provider_store.get_run_binding(run_id=run_id)
        if binding["profile_hash"] != provider.profile_hash:
            raise MaxControlError("live runner provider profile differs from the run binding")
        bundle_status = self.bundle_store.status(run_id=run_id, bundle_id=bundle_id)
        if bundle_status["count"] != 1:
            raise MaxControlError("live runner authorization bundle was not found")
        bundle = bundle_status["bundles"][0]
        if bundle["grant_id"] != grant_id or bundle["profile_hash"] != provider.profile_hash or bundle["state"] not in {"active", "exhausted"}:
            raise MaxControlError("live runner authorization bundle binding is invalid")
        # The handoff is an explicit prior admin action.  claim_runner_lease
        # only renews the exact same owner/session/profile and never creates a
        # new handoff.  BoundedRunner repeats this idempotent renewal.
        persistence = RunnerPersistence(self.repository)
        lease = persistence.claim_runner_lease(run_id=run_id, profile=runner, actor=self.actor, lease_ttl=lease_ttl)
        LiveIterationApprovalStore(self.repository).consume(live_iteration_approval_id=live_iteration_approval_id, run_id=run_id, grant_id=grant_id, bundle_id=bundle_id, provider_profile_hash=provider.profile_hash, runner_profile_hash=runner.profile_hash, actor=self.actor, fencing_token=int(lease["fencing_token"]))
        grant_status = self.provider_store.grant_status(run_id=run_id)
        grant = next((item for item in grant_status.get("grants", ()) if item.get("grant_id") == grant_id), None)
        if not isinstance(grant, Mapping) or grant.get("profile_hash") != provider.profile_hash or not grant.get("active", False):
            raise MaxControlError("live runner execution grant is missing, expired, or mismatched")
        # The one-shot execution grant is consumed before its live-network
        # authorities are issued.  Do not attempt to transfer/re-consume that
        # immutable authority under the runner identity here.
        if not isinstance(grant.get("consumption"), Mapping):
            raise MaxControlError("live runner execution grant has not been consumed by its authority workflow")
        self.repository.usage_authority = self.usage_authority
        adapter = LiveAuthorizationPoolAdapter(
            provider,
            provider_store=self.provider_store,
            bundle_store=self.bundle_store,
            bundle_id=bundle_id,
            actor=self.actor,
            grant_id=grant_id,
            fencing_token=int(lease["fencing_token"]),
            transport_factory=self.transport_factory,
            usage_authority=self.usage_authority,
        )
        bounded = BoundedRunner(
            self.repository,
            self.actor,
            runner,
            adapter,
            gateway=gateway,
            usage_authority=self.usage_authority,
            fixture=False,
            lease_ttl=lease_ttl,
        )
        result = bounded.run_next(run_id=run_id)
        # Only the runner's already-redacted summary is returned.  Provider
        # bodies, credentials, endpoint values and fencing tokens stay local.
        return dict(result)


__all__ = ["LIVE_EXECUTION_ACK", "LiveIterationApprovalStore", "LiveRunnerExecutor", "live_execution_confirmation_hash"]
