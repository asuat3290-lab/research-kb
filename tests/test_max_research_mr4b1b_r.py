"""MR-4B1B-R offline Source Permit and boundary regression tests."""

from __future__ import annotations

import json
import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from research_kb import __version__
from research_kb.max_research.contract import ResearchState, canonical_sha256, model_to_dict
from research_kb.max_research.live_canary import LiveCanaryAuthorityError, LiveCanaryAuthorityStore
from research_kb.max_research.long_run import SourceEgressStore
from research_kb.max_research.persistence.repository import MaxControlRepository
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION
from research_kb.max_research.persistence.db import MaxControlError
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.production_bridge import LiveCanaryExecutor
from research_kb.max_research.provider import ProviderProfile, ProviderStore, TransportResponse, network_policy_hash
from research_kb.max_research.runner import InferenceProfile, ModelRequestEnvelope
from research_kb.max_research.runner.contracts import ModelCallIntent
from research_kb.max_research.runner.planner import build_plan
from research_kb.max_research.scheduler import provider_runner_profile
from research_kb.policy import Actor


def _network_policy() -> dict[str, str]:
    return {"policy_version": "mr4b1b-r-offline/v1"}


def _profile_mapping() -> dict:
    return {
        "profile_id": "mr4b1b-r-profile",
        "profile_version": "1",
        "protocol": "openai-compatible/v1",
        "provider_name": "offline-provider-placeholder",
        "model_identity": "offline-model-placeholder/v1",
        "endpoint_origin": "https://provider.invalid",
        "endpoint_path_policy": "/v1/chat/completions",
        "capabilities": {"structured_json": True, "idempotency": True, "result_query": False, "usage_reporting": True},
        "inference_defaults": {"temperature": 0, "top_p": 1, "max_output_tokens": 32},
        "timeout_policy": {"connect_ms": 1000, "write_ms": 1000, "read_ms": 1000, "total_ms": 5000},
        "retry_policy": {"max_attempts": 1, "backoff_ms": 1, "retry_statuses": [429]},
        "request_limits": {"max_request_bytes": 100000, "max_response_bytes": 100000, "max_prompt_chars": 10000, "max_json_depth": 12, "max_input_tokens": 512, "max_output_tokens": 32, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0},
        "rate_policy": {"max_concurrency": 1, "per_minute": 60},
        "credential_ref": {"kind": "environment", "name": "MR4B1B_R_OFFLINE_FIXTURE"},
        "network_policy_hash": network_policy_hash(_network_policy()),
        "pricing": {"pricing_id": "mr4b1b-r-price", "pricing_version": "1", "currency": "USD", "unit": "cost_units", "input_per_1k": "1", "output_per_1k": "2", "cache_per_1k": "0", "reasoning_per_1k": "0", "effective_at": "2026-01-01T00:00:00.000Z", "source_label": "offline-fixture"},
    }


class _CountingTransport:
    def __init__(self, *, raise_on_send: bool = False, response: TransportResponse | None = None) -> None:
        self.calls = 0
        self.dns_lookup_count = 0
        self.credential_read_count = 0
        self.network_call_count = 0
        self.raise_on_send = raise_on_send
        self.response = response

    def bind_server_permit(self, _permit) -> None:
        return None

    def send(self, _request, *, headers, timeout_ms, idempotency_key) -> TransportResponse:
        del headers, timeout_ms, idempotency_key
        self.calls += 1
        self.network_call_count += 1
        if self.raise_on_send:
            raise RuntimeError("injected transport send failure")
        return self.response or TransportResponse(
            200,
            {"id": "mr4b1b-r-provider-call", "usage": {"prompt_tokens": 4, "completion_tokens": 2}},
            {"content-type": "application/json"},
            "mr4b1b-r-provider-call",
            True,
        )


class MR4B1BRTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr4b1b-r-")
        self.root = Path(self.temp.name)
        self.database = self.root / "control.db"
        self.admin = Actor("mr4b1br-admin", "mr4b1br-admin-session", "user", "admin", "mr4b1b-r-tests")
        self.worker = Actor("mr4b1br-worker", "mr4b1br-worker-session", "worker", "runner", "mr4b1b-r-tests")
        self.repo = MaxControlRepository(self.database)
        self.repo.initialize(fixture=True)
        self.store = ProviderStore(self.repo)
        registered = self.store.register_profile(profile=ProviderProfile.from_mapping(_profile_mapping()), actor=self.admin)
        self.profile = self.store.get_profile(profile_hash=registered["profile_hash"])
        self.store.register_network_policy(policy=_network_policy(), actor=self.admin)
        charter = {
            "question": "MR-4B1B-R source permit boundary",
            "scope": "offline fixture",
            "invariants": ["one-shot", "bounded"],
            "non_goals": ["network"],
            "deliverables": ["audit"],
            "model_identity": self.profile.model_identity,
            "budget": {"iteration_count": 2, "input_tokens": 10000, "output_tokens": 10000, "cost_units": 1000},
            "source_policy": {"network_allowed": False, "roles": ["primary"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        proposed = self.repo.propose(project_id="mr4b1b-r-project", charter=charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="offline MR-4B1B-R fixture", actor=self.admin)
        started = self.repo.start(run_id=proposed["run_id"], actor=self.admin, lease_ttl=300)
        self.run_id = proposed["run_id"]
        self.store.bind_run_profile(run_id=self.run_id, profile_hash=self.profile.profile_hash, actor=self.admin)
        runner_profile = provider_runner_profile(self.profile)
        persistence = RunnerPersistence(self.repo)
        persistence.register_profile(profile=runner_profile, actor=self.admin)
        handoff = persistence.handoff_runner(run_id=self.run_id, profile=runner_profile, admin_actor=self.admin, runner_actor=self.worker, admin_fencing_token=int(started["lease"]["fencing_token"]), lease_ttl=300)
        self.fencing_token = int(handoff["lease"]["fencing_token"])
        claim = persistence.claim_invocation(run_id=self.run_id, actor=self.worker, fencing_token=self.fencing_token, ttl_seconds=300)
        self.claim_id = claim["claim_id"]
        self.runner_profile = runner_profile
        state = ResearchState.from_mapping(self.repo.get_state(run_id=self.run_id))
        plan = build_plan(project_id="mr4b1b-r-project", run_id=self.run_id, sequence=1, state=model_to_dict(state), history=(), profile=runner_profile)
        self.repo.begin_iteration(run_id=self.run_id, round_type=plan.round_type, actor=self.worker, fencing_token=self.fencing_token, input_state_hash=plan.input_state_hash, iteration_id=plan.iteration_id, requested_sequence=1)
        persistence.record_plan(run_id=self.run_id, plan=plan, profile=runner_profile, actor=self.worker, fencing_token=self.fencing_token)
        persistence.bind_plan(run_id=self.run_id, plan_id=plan.plan_id, iteration_id=plan.iteration_id, actor=self.worker, fencing_token=self.fencing_token)
        group = persistence.record_call_group(run_id=self.run_id, plan=plan, actor=self.worker, fencing_token=self.fencing_token)
        packet = plan.role_packets[0]
        request = ModelRequestEnvelope(project_id="mr4b1b-r-project", run_id=self.run_id, iteration_id=plan.iteration_id, role_packet=packet, model_identity=self.profile.model_identity, inference_profile=InferenceProfile(max_output_tokens=32, timeout_seconds=5), context={"provider_profile_hash": self.profile.profile_hash, "gateway_name": "offline", "canonical_ids": []}, request_payload={"phase": "exploration", "logical_call_id": "mr4b1b-r-logical-call"})
        self.intent = ModelCallIntent(project_id=request.project_id, run_id=request.run_id, iteration_id=request.iteration_id, input_state_hash=plan.input_state_hash, role_packet_id=packet.packet_id, round_type=plan.round_type, model_identity=self.profile.model_identity, inference_profile_hash=runner_profile.inference_profile.inference_profile_hash, request_hash=request.request_hash, idempotency_key="mr4b1b-r-idempotency", request=request, logical_call_id="mr4b1b-r-logical-call")
        persistence.record_intent(run_id=self.run_id, intent=self.intent, plan_id=plan.plan_id, actor=self.worker, fencing_token=self.fencing_token, group_id=group["group_id"], call_index=0, phase=plan.call_specs[0].phase)
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=180)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        policy = SourceEgressStore(self.repo).create_policy(
            run_id=self.run_id,
            value={
                "allowed_purposes": ["supports"],
                "allow_document_ids": ["d1"],
                "allow_passage_ids": ["p1"],
                "allowed_source_versions": ["v1"],
                "deny_document_ids": [],
                "source_role_policy": {"allowed_roles": ["primary"], "allowed_functions": ["supports"]},
                "reliability_policy": {"allowed_statuses": ["reviewed"]},
                "verification_policy": {"allowed_statuses": ["verified"]},
                "max_packets": 1,
                "max_documents": 1,
                "max_passages": 1,
                "max_excerpt_characters": 2000,
                "max_context_characters": 0,
                "max_document_characters": 2000,
                "max_passage_characters": 2000,
                "max_source_characters": 2000,
                "max_source_tokens": 512,
                "max_packet_source_tokens": 512,
                "full_document_prohibited": True,
                "expires_at": expiry,
                "authority_reason": "MR-4B1B-R offline source permit test",
            },
            actor=self.admin,
        )
        self.policy_hash = policy["policy_hash"]
        with closing(self.repo._connect(read_only=True)) as connection:
            durable_source_policy = json.loads(connection.execute("SELECT policy_json FROM max_source_egress_policies WHERE policy_hash=?", (self.policy_hash,)).fetchone()[0])
        run = self.repo.get_run(run_id=self.run_id)
        binding = self.store.get_run_binding(run_id=self.run_id)
        origin_hash, path_hash = self._endpoint_hashes()
        maximum_cost = self.profile.pricing.cost_units_for_usage(self.profile.authority_maximum_usage())
        h = "a" * 64
        self.authority = LiveCanaryAuthorityStore(self.repo)
        self.authority_candidate = {
            "project_id": run["project_id"],
            "run_id": self.run_id,
            "charter_hash": run["charter_hash"],
            "current_state_hash": run["current_state_hash"],
            "current_checkpoint_id": run["current_checkpoint_id"],
            "current_state_version": run["state_version"],
            "engine_package": "research-kb",
            "engine_version": __version__,
            "core_schema_version": 5,
            "control_schema_version": CONTROL_SCHEMA_VERSION,
            "candidate_wheel_sha256": h,
            "source_manifest_sha256": h,
            "source_tree_sha256": h,
            "provider_profile_hash": self.profile.profile_hash,
            "provider_name": self.profile.provider_name,
            "model_identity": self.profile.model_identity,
            "model_version": self.profile.model_revision or "provider-managed-alias",
            "pricing_hash": self.profile.pricing.pricing_hash,
            "budget_hash": run["budget_hash"],
            "endpoint_origin_hash": origin_hash,
            "endpoint_path_policy_hash": path_hash,
            "network_policy_hash": self.profile.network_policy_hash,
            "credential_ref_hash": self._credential_hash(),
            "source_egress_policy_hash": self.policy_hash,
            "source_allowlist": [{"project_id": run["project_id"], "passage_id": "p1", "document_id": "d1", "document_version_id": "v1", "source_role": "primary", "evidential_function": "supports", "verification_status": "verified", "reliability_status": "reviewed"}],
            "source_policy": durable_source_policy,
            "runner_profile_hash": runner_profile.profile_hash,
            "worker_id": self.worker.actor_id,
            "worker_session": self.worker.session_id,
            "fencing_token": self.fencing_token,
            "claim_id": self.claim_id,
            "caps": {"max_provider_calls": 1, "max_ticks": 1, "max_iterations": 1, "max_acquisition_requests": 0, "max_ocr_requests": 0, "max_ingest_operations": 0, "max_input_tokens": 512, "max_output_tokens": 32, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": maximum_cost, "max_wall_clock_seconds": 60, "max_source_passages": 1, "max_source_characters": 2000},
            "transport_policy": {"redirect": False, "retry": False, "timeout_seconds": 30},
            "kill_rollback_incident_policy": {"kill": "revoke", "rollback": "stop", "incident": "pause"},
        }
        self.authority_expiry = expiry
        self.authority_registration = self.authority.register_authority(value=self.authority_candidate, expires_at=expiry, actor=self.admin)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _endpoint_hashes(self) -> tuple[str, str]:
        from research_kb.max_research.provider.live import endpoint_hashes
        return endpoint_hashes(self.profile.endpoint_origin, self.profile.endpoint_path_policy)

    def _credential_hash(self) -> str:
        from research_kb.max_research.provider.live import credential_reference_hash
        return credential_reference_hash(self.profile.credential_ref)

    def _prepared_canary(self) -> tuple[dict, dict, dict]:
        registration = self.authority_registration
        expiry = registration["authority"]["request_manifest_hash"]
        self.authority.preview_from_authority(authority_id=registration["authority_id"], actor=self.worker)
        approval = self.authority.authorize(
            preview_id=registration["preview_id"],
            preview_hash=registration["preview_hash"],
            confirmation_phrase=f"APPROVE MR-4B1 CANARY {registration['preview_hash']}",
            expires_at=(datetime.now(timezone.utc) + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z",
            actor=self.admin,
            reason="offline MR-4B1B-R approval fixture",
        )
        authority_value = registration["authority"]
        prepared = self.authority.consume_and_prepare(
            approval_id=approval["approval_id"],
            preview_hash=registration["preview_hash"],
            consumer=self.worker,
            worker_id=self.worker.actor_id,
            worker_session=self.worker.session_id,
            fencing_token=self.fencing_token,
            claim_id=self.claim_id,
            request_hash=self.intent.request_hash,
            idempotency_key_hash=canonical_sha256(self.intent.idempotency_key),
        )
        manifest = {
            "manifest_hash": expiry,
            "project_id": authority_value["project_id"],
            "run_id": authority_value["run_id"],
            "passage_id": "p1",
            "document_id": "d1",
            "source_version": "v1",
            "source_policy_hash": self.policy_hash,
            "logical_call_id": self.intent.logical_call_id,
            "provider_profile_hash": self.profile.profile_hash,
            "source_role": "primary",
            "evidential_function": "supports",
            "purpose": "supports",
        }
        return approval, prepared, manifest

    def _execution_inputs(self) -> tuple[dict, dict, dict]:
        registration = self.authority_registration
        preview = self.authority.preview_from_authority(authority_id=registration["authority_id"], actor=self.worker)
        approval = self.authority.authorize(
            preview_id=registration["preview_id"],
            preview_hash=registration["preview_hash"],
            confirmation_phrase=f"APPROVE MR-4B1 CANARY {registration['preview_hash']}",
            expires_at=(datetime.now(timezone.utc) + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z",
            actor=self.admin,
            reason="offline MR-4B1B-R executor fixture",
        )
        maximum_cost = self.profile.pricing.cost_units_for_usage(self.profile.authority_maximum_usage())
        grant = self.store.issue_live_execution_grant(
            run_id=self.run_id,
            profile_hash=self.profile.profile_hash,
            caps={"max_ticks": 1, "max_iterations": 1, "max_wall_clock_seconds": 60, "max_consecutive_failures": 1, "max_no_progress": 1, "max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cost_units": maximum_cost},
            reason="MR-4B1B-R executor fixture grant",
            actor=self.admin,
        )
        binding = self.store.get_run_binding(run_id=self.run_id)
        self.store.consume_execution_grant(
            grant_id=grant["grant_id"],
            run_id=self.run_id,
            project_id=binding["project_id"],
            profile_hash=self.profile.profile_hash,
            model_identity=self.profile.model_identity,
            network_policy_hash=self.profile.network_policy_hash,
            pricing_hash=self.profile.pricing.pricing_hash,
            budget_hash=binding["budget_hash"],
            consumer=self.worker,
        )
        authorization = self.store.issue_live_network_authorization(
            run_id=self.run_id,
            grant_id=grant["grant_id"],
            caps={"max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": maximum_cost},
            network_policy=_network_policy(),
            reason="MR-4B1B-R executor fixture network grant",
            actor=self.admin,
            ttl_seconds=120,
            profile_hash=self.profile.profile_hash,
        )
        return preview, {"approval": approval, "grant": grant, "authorization": authorization}, registration

    def _run_executor_fault(self, *, mark_after: bool) -> tuple[LiveCanaryExecutor, _CountingTransport, Exception]:
        preview, inputs, registration = self._execution_inputs()
        fake = _CountingTransport()
        executor = LiveCanaryExecutor(self.repo, self.authority, provider_store=self.store, transport=fake, live_network_enabled=True)
        original = self.authority.mark_http_dispatch_boundary_crossed

        def injected(*, permit_id: str, run_id: str, project_id: str, claim_id: str, attempt_id: str, fencing_token: int, request_hash: str, idempotency_key_hash: str, actor: Actor, canary_claim_id: str | None = None) -> dict:
            if mark_after:
                result = original(
                    permit_id=permit_id,
                    run_id=run_id,
                    project_id=project_id,
                    claim_id=claim_id,
                    attempt_id=attempt_id,
                    fencing_token=fencing_token,
                    request_hash=request_hash,
                    idempotency_key_hash=idempotency_key_hash,
                    actor=actor,
                    canary_claim_id=canary_claim_id,
                )
                raise LiveCanaryAuthorityError("injected after durable send boundary")
            raise LiveCanaryAuthorityError("injected before durable send boundary")

        self.authority.mark_http_dispatch_boundary_crossed = injected  # type: ignore[method-assign]
        try:
            executor.execute_fixture(
                authority_id=registration["authority_id"],
                approval_id=inputs["approval"]["approval_id"],
                preview_hash=preview["preview_hash"],
                confirmation_phrase=preview["confirmation_phrase"],
                actor=self.worker,
                worker_id=self.worker.actor_id,
                worker_session=self.worker.session_id,
                fencing_token=self.fencing_token,
                claim_id=self.claim_id,
                request={"phase": "offline-fixture"},
                logical_call_id=self.intent.logical_call_id,
                idempotency_key=self.intent.idempotency_key,
                authorization_id=inputs["authorization"]["authorization_id"],
                grant_id=inputs["grant"]["grant_id"],
                source_permit_validator=lambda: True,
                allow_execute=True,
            )
        except Exception as exc:
            return executor, fake, exc
        finally:
            self.authority.mark_http_dispatch_boundary_crossed = original  # type: ignore[method-assign]
        raise AssertionError("fault injection did not fail")

    def _run_dispatch_stage_fault(self, stage: str) -> tuple[_CountingTransport, Exception]:
        preview, inputs, registration = self._execution_inputs()
        fake = _CountingTransport()
        executor = LiveCanaryExecutor(self.repo, self.authority, provider_store=self.store, transport=fake, live_network_enabled=True)
        if stage == "dispatch_prepare":
            original = self.store.prepare_live_dispatch

            def injected(*_args, **_kwargs):
                raise MaxControlError("injected dispatch prepare failure")

            self.store.prepare_live_dispatch = injected  # type: ignore[method-assign]
        elif stage == "dispatch_start":
            original = self.store.start_live_dispatch

            def injected(*_args, **_kwargs):
                raise MaxControlError("injected dispatch start failure")

            self.store.start_live_dispatch = injected  # type: ignore[method-assign]
        else:
            raise AssertionError(stage)
        try:
            with self.assertRaises(Exception) as caught:
                executor.execute_fixture(
                    authority_id=registration["authority_id"], approval_id=inputs["approval"]["approval_id"], preview_hash=preview["preview_hash"], confirmation_phrase=preview["confirmation_phrase"], actor=self.worker,
                    worker_id=self.worker.actor_id, worker_session=self.worker.session_id, fencing_token=self.fencing_token, claim_id=self.claim_id,
                    request={"phase": "offline-fixture"}, logical_call_id=self.intent.logical_call_id, idempotency_key=self.intent.idempotency_key,
                    authorization_id=inputs["authorization"]["authorization_id"], grant_id=inputs["grant"]["grant_id"], source_permit_validator=lambda: True, allow_execute=True,
                )
        finally:
            if stage == "dispatch_prepare":
                self.store.prepare_live_dispatch = original  # type: ignore[method-assign]
            else:
                self.store.start_live_dispatch = original  # type: ignore[method-assign]
        return fake, caught.exception

    def _assert_pre_send_runner_closed(self) -> None:
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT status FROM max_runs").fetchone()[0], "PAUSED")
            self.assertEqual(connection.execute("SELECT status FROM max_runner_call_group_current").fetchone()[0], "aborted")
            self.assertEqual(connection.execute("SELECT status FROM max_iteration_outcomes").fetchone()[0], "aborted")
            self.assertEqual(connection.execute("SELECT status FROM max_runner_attempt_outcomes").fetchone()[0], "aborted")
            self.assertIsNone(connection.execute("SELECT 1 FROM max_runner_plan_current").fetchone())
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_usage_attestations").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records").fetchone()[0], 0)

    def test_source_permit_issue_consume_and_sql_arity(self) -> None:
        approval, prepared, manifest = self._prepared_canary()
        issued = self.authority.issue_source_permit(
            authority_id=self.authority_registration["authority_id"],
            approval_id=approval["approval_id"],
            canary_permit_id=prepared["permit_id"],
            manifest=manifest,
            worker_id=self.worker.actor_id,
            worker_session=self.worker.session_id,
            fencing_token=self.fencing_token,
            actor=self.worker,
        )
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_source_permits").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_source_permit_current").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_source_permit_events").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT state FROM max_live_canary_source_permit_current WHERE source_permit_id=?", (issued["source_permit_id"],)).fetchone()[0], "issued")
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        self.authority.consume_source_permit(
            source_permit_id=issued["source_permit_id"],
            manifest_hash=manifest["manifest_hash"],
            worker_id=self.worker.actor_id,
            worker_session=self.worker.session_id,
            fencing_token=self.fencing_token,
            actor=self.worker,
        )
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT state FROM max_live_canary_source_permit_current WHERE source_permit_id=?", (issued["source_permit_id"],)).fetchone()[0], "consumed")
            events = list(connection.execute("SELECT sequence_no,event_type FROM max_live_canary_source_permit_events WHERE source_permit_id=? ORDER BY sequence_no", (issued["source_permit_id"],)))
            self.assertEqual([(row[0], row[1]) for row in events], [(1, "source_permit_issued"), (2, "source_permit_consumed")])
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        with self.assertRaises(LiveCanaryAuthorityError):
            self.authority.consume_source_permit(
                source_permit_id=issued["source_permit_id"],
                manifest_hash=manifest["manifest_hash"],
                worker_id=self.worker.actor_id,
                worker_session=self.worker.session_id,
                fencing_token=self.fencing_token,
                actor=self.worker,
            )

    def test_source_permit_insert_sql_has_fourteen_placeholders_in_both_paths(self) -> None:
        source = (Path(__file__).parents[1] / "src" / "research_kb" / "max_research" / "live_canary.py").read_text(encoding="utf-8")
        statement = "INSERT INTO max_live_canary_source_permit_events(source_permit_event_id,source_permit_id,project_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        self.assertEqual(source.count(statement), 3)
        self.assertEqual(statement.split("VALUES ", 1)[1].count("?"), 14)

    def test_opencode_pricing_ceiling_rounds_728_2688_to_729(self) -> None:
        mapping = _profile_mapping()
        mapping.update({
            "profile_id": "opencode-go-deepseek-v4-flash-test",
            "provider_name": "opencode-go",
            "model_identity": "deepseek-v4-flash",
            "endpoint_origin": "https://opencode.ai",
            "endpoint_path_policy": "/zen/go/v1/chat/completions",
            "request_limits": {
                "max_request_bytes": 65536,
                "max_response_bytes": 262144,
                "max_prompt_chars": 12000,
                "max_json_depth": 16,
                "max_input_tokens": 4096,
                "max_output_tokens": 256,
                "max_cache_read_tokens": 4096,
                "max_reasoning_tokens": 256,
            },
            "inference_defaults": {
                "temperature": 0,
                "max_input_tokens": 4096,
                "max_output_tokens": 256,
                "max_cache_read_tokens": 4096,
                "max_reasoning_tokens": 256,
            },
            "pricing": {
                "pricing_id": "opencode-go-deepseek-v4-flash-test",
                "pricing_version": "2026-08-14",
                "currency": "USD",
                "unit": "micro_usd",
                "input_per_1k": "140.0",
                "output_per_1k": "280.0",
                "cache_per_1k": "2.8",
                "reasoning_per_1k": "280.0",
                "effective_at": "2026-08-14T00:00:00.000Z",
                "source_label": "offline-fixture",
            },
        })
        profile = ProviderProfile.from_mapping(mapping)
        self.assertEqual(profile.authority_maximum_usage(), {"cache_read_tokens": 4096, "input_tokens": 4096, "output_tokens": 256, "reasoning_tokens": 256})
        self.assertEqual(profile.pricing.cost_units_for_usage(profile.authority_maximum_usage()), 729)

    def test_execution_plan_preflight_exports_effective_provider_cap(self) -> None:
        plan = self.authority.validate_live_execution_plan(
            authority_id=self.authority_registration["authority_id"],
            preview_hash=self.authority_registration["preview_hash"],
        )
        self.assertTrue(plan["execution_plan_ok"], plan.get("reasons"))
        self.assertEqual(plan["human_cost_ceiling"], 1)
        self.assertEqual(plan["profile_worst_case_cost"], 1)
        self.assertEqual(plan["effective_provider_cost_cap"], 1)
        self.assertEqual(plan["grant_caps"]["max_cost_units"], 1)
        self.assertEqual(plan["network_authorization_caps"]["max_cost_units"], 1)
        self.assertTrue(plan["network_authorization_feasible"])
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_authorizations").fetchone()[0], 0)

    def test_human_cost_ceiling_below_profile_blocks_authorization(self) -> None:
        candidate = json.loads(json.dumps(self.authority_candidate))
        candidate["caps"]["max_cost_units"] = 0
        candidate["human_cost_ceiling"] = 0
        candidate["profile_worst_case_cost"] = 1
        candidate["effective_provider_cost_cap"] = 0
        registration = self.authority.register_authority(
            value=candidate,
            expires_at=self.authority_expiry,
            actor=self.admin,
        )
        plan = self.authority.validate_live_execution_plan(authority_id=registration["authority_id"])
        self.assertFalse(plan["execution_plan_ok"])
        self.assertFalse(plan["network_authorization_feasible"])
        self.assertIn("human_cost_ceiling_below_profile_worst_case", plan["reasons"])
        with self.assertRaises(LiveCanaryAuthorityError):
            self.authority.authorize(
                preview_id=registration["preview_id"],
                preview_hash=registration["preview_hash"],
                confirmation_phrase=f"APPROVE MR-4B1 CANARY {registration['preview_hash']}",
                expires_at=(datetime.now(timezone.utc) + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z",
                actor=self.admin,
                reason="effective cap must block approval",
            )
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals").fetchone()[0], 0)

    def test_network_cost_cap_overage_has_stable_error_code(self) -> None:
        _preview, inputs, _registration = self._execution_inputs()
        maximum_cost = self.profile.pricing.cost_units_for_usage(self.profile.authority_maximum_usage())
        grant = self.store.issue_live_execution_grant(
            run_id=self.run_id,
            profile_hash=self.profile.profile_hash,
            caps={"max_ticks": 1, "max_iterations": 1, "max_wall_clock_seconds": 60, "max_consecutive_failures": 1, "max_no_progress": 1, "max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cost_units": maximum_cost},
            reason="stable cost error fixture",
            actor=self.admin,
        )
        binding = self.store.get_run_binding(run_id=self.run_id)
        self.store.consume_execution_grant(
            grant_id=grant["grant_id"],
            run_id=self.run_id,
            project_id=binding["project_id"],
            profile_hash=self.profile.profile_hash,
            model_identity=self.profile.model_identity,
            network_policy_hash=self.profile.network_policy_hash,
            pricing_hash=self.profile.pricing.pricing_hash,
            budget_hash=binding["budget_hash"],
            consumer=self.worker,
        )
        with self.assertRaises(MaxControlError) as caught:
            self.store.issue_live_network_authorization(
                run_id=self.run_id,
                grant_id=grant["grant_id"],
                caps={"max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": maximum_cost + 1},
                network_policy=_network_policy(),
                reason="over-cap fixture",
                actor=self.admin,
                ttl_seconds=120,
                profile_hash=self.profile.profile_hash,
            )
        self.assertEqual(caught.exception.error_code, "LIVE_AUTH_COST_CAP_EXCEEDS_PROFILE_MAXIMUM")
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_authorizations").fetchone()[0], 1)

    def test_pricing_hash_drift_fails_closed_before_authority_registration(self) -> None:
        candidate = json.loads(json.dumps(self.authority_candidate))
        candidate["pricing_hash"] = "0" * 64
        with self.assertRaises(LiveCanaryAuthorityError):
            self.authority.register_authority(
                value=candidate,
                expires_at=self.authority_expiry,
                actor=self.admin,
            )
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_authority_bindings").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals").fetchone()[0], 0)

    def test_durable_boundary_classification_and_redacted_diagnostics(self) -> None:
        _approval, prepared, _manifest = self._prepared_canary()
        before = self.authority.classify_provider_boundary(permit_id=prepared["permit_id"])
        self.assertEqual(before["failure_class"], "KNOWN_PRE_SEND_FAILURE")
        self.assertFalse(before["send_boundary_reached"])
        self.assertFalse(before["reconciliation_required"])
        self.authority.mark_send_started(permit_id=prepared["permit_id"], actor=self.worker)
        after = self.authority.classify_provider_boundary(permit_id=prepared["permit_id"])
        self.assertEqual(after["failure_class"], "UNKNOWN_AFTER_SEND")
        self.assertTrue(after["send_boundary_reached"])
        self.assertTrue(after["reconciliation_required"])
        diagnostics = {
            "failure_stage": "mark_send_started",
            "failure_class": after["failure_class"],
            "exception_type": "InjectedBoundaryError",
            "send_boundary_reached": True,
            "reconciliation_required": True,
            "retry_allowed": False,
            "durable_evidence": after["durable_evidence"],
        }
        self.authority.record_outcome(permit_id=prepared["permit_id"], outcome="unknown", usage={}, cost_units=0, actor=self.worker, diagnostics=diagnostics)
        with closing(self.repo._connect(read_only=True)) as connection:
            row = connection.execute("SELECT outcome_json FROM max_live_canary_outcomes WHERE permit_id=?", (prepared["permit_id"],)).fetchone()
            value = json.loads(row[0])
            self.assertEqual(value["diagnostics"]["failure_class"], "UNKNOWN_AFTER_SEND")
            self.assertFalse(value["diagnostics"]["retry_allowed"])
            serialized = json.dumps(value, ensure_ascii=False)
            for forbidden in ("traceback", "source_text", "api_key", "credential_value", "request_body", "response_body"):
                self.assertNotIn(forbidden, serialized.casefold())

    def test_pre_send_provider_abort_releases_reservation_without_network_attempt(self) -> None:
        _approval, prepared, _manifest = self._prepared_canary()
        maximum_cost = self.profile.pricing.cost_units_for_usage(self.profile.authority_maximum_usage())
        grant = self.store.issue_live_execution_grant(
            run_id=self.run_id,
            profile_hash=self.profile.profile_hash,
            caps={"max_ticks": 1, "max_iterations": 1, "max_wall_clock_seconds": 60, "max_consecutive_failures": 1, "max_no_progress": 1, "max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cost_units": maximum_cost},
            reason="MR-4B1B-R pre-send cleanup fixture",
            actor=self.admin,
        )
        binding = self.store.get_run_binding(run_id=self.run_id)
        self.store.consume_execution_grant(
            grant_id=grant["grant_id"],
            run_id=self.run_id,
            project_id=binding["project_id"],
            profile_hash=self.profile.profile_hash,
            model_identity=self.profile.model_identity,
            network_policy_hash=self.profile.network_policy_hash,
            pricing_hash=self.profile.pricing.pricing_hash,
            budget_hash=binding["budget_hash"],
            consumer=self.worker,
        )
        authorization = self.store.issue_live_network_authorization(
            run_id=self.run_id,
            grant_id=grant["grant_id"],
            caps={"max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": maximum_cost},
            network_policy=_network_policy(),
            reason="MR-4B1B-R pre-send cleanup network authority",
            actor=self.admin,
            ttl_seconds=120,
            profile_hash=self.profile.profile_hash,
        )
        prepared_dispatch = self.store.prepare_live_dispatch(
            authorization_id=authorization["authorization_id"],
            run_id=self.run_id,
            project_id="mr4b1b-r-project",
            grant_id=grant["grant_id"],
            profile=self.profile,
            request_hash=self.intent.request_hash,
            wire_request_hash=hashlib.sha256(b"offline-wire").hexdigest(),
            intent_hash=self.intent.intent_hash,
            logical_call_id=self.intent.logical_call_id,
            idempotency_key=self.intent.idempotency_key,
            actor=self.worker,
            fencing_token=self.fencing_token,
        )
        provider_permit = self.store.start_live_dispatch(permit=prepared_dispatch["permit"], actor=self.worker, fencing_token=self.fencing_token)
        before = self.authority.classify_provider_boundary(permit_id=prepared["permit_id"])
        self.assertEqual(before["failure_class"], "KNOWN_PRE_SEND_FAILURE")
        self.store.abort_live_dispatch_before_send(
            permit=provider_permit,
            actor=self.worker,
            fencing_token=self.fencing_token,
            details={"failure_stage": "mark_send_started", "exception_type": "InjectedBoundaryError"},
        )
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT state FROM max_live_dispatch_permit_current WHERE permit_id=?", (provider_permit.permit_id,)).fetchone()[0], "failed")
            self.assertEqual(connection.execute("SELECT state FROM max_provider_dispatch_attempt_current WHERE attempt_id=?", (provider_permit.attempt_id,)).fetchone()[0], "cancelled")
            self.assertEqual(connection.execute("SELECT state FROM max_provider_call_claim_current WHERE claim_id=?", (provider_permit.claim_id,)).fetchone()[0], "released")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records WHERE authorization_id=?", (authorization["authorization_id"],)).fetchone()[0], 0)
            usage = json.loads(connection.execute("SELECT current_json FROM max_provider_grant_usage_current WHERE grant_id=?", (grant["grant_id"],)).fetchone()[0])
            self.assertEqual(usage["reserved_cost_units"], 0)
            self.assertGreater(usage["released_cost_units"], 0)
        verified = self.store.verify(run_id=self.run_id)
        self.assertTrue(verified["ok"], verified.get("issues"))

    def test_hermetic_executor_success_calls_fake_transport_once_and_settles(self) -> None:
        preview, inputs, registration = self._execution_inputs()
        fake = _CountingTransport()
        executor = LiveCanaryExecutor(self.repo, self.authority, provider_store=self.store, transport=fake, live_network_enabled=True)
        result = executor.execute_fixture(
            authority_id=registration["authority_id"],
            approval_id=inputs["approval"]["approval_id"],
            preview_hash=preview["preview_hash"],
            confirmation_phrase=preview["confirmation_phrase"],
            actor=self.worker,
            worker_id=self.worker.actor_id,
            worker_session=self.worker.session_id,
            fencing_token=self.fencing_token,
            claim_id=self.claim_id,
            request={"phase": "offline-fixture"},
            logical_call_id=self.intent.logical_call_id,
            idempotency_key=self.intent.idempotency_key,
            authorization_id=inputs["authorization"]["authorization_id"],
            grant_id=inputs["grant"]["grant_id"],
            source_permit_validator=lambda: True,
            allow_execute=True,
        )
        self.assertEqual(result["outcome"], "succeeded")
        self.assertTrue(result["source_permit_id"])
        self.assertEqual(fake.calls, 1)
        self.assertEqual(result["network"]["provider_calls"], 1)
        verified = self.store.verify(run_id=self.run_id)
        self.assertTrue(verified["ok"], verified.get("issues"))
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_call_records WHERE run_id=?", (self.run_id,)).fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records WHERE authorization_id=?", (inputs["authorization"]["authorization_id"],)).fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT state FROM max_live_canary_source_permit_current WHERE source_permit_id=?", (result["source_permit_id"],)).fetchone()[0], "consumed")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_source_permit_events WHERE source_permit_id=?", (result["source_permit_id"],)).fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT outcome FROM max_live_canary_outcomes WHERE permit_id=?", (result["permit_id"],)).fetchone()[0], "succeeded")

    def test_mark_send_started_before_is_known_pre_send_and_never_retried(self) -> None:
        _executor, fake, error = self._run_executor_fault(mark_after=False)
        self.assertIn("KNOWN_PRE_SEND_FAILURE", str(error))
        self.assertEqual(fake.calls, 0)
        with closing(self.repo._connect(read_only=True)) as connection:
            outcome = connection.execute("SELECT permit_id, outcome_json FROM max_live_canary_outcomes ORDER BY created_at DESC LIMIT 1").fetchone()
            value = json.loads(outcome[1])
            self.assertEqual(value["outcome"], "aborted")
            self.assertEqual(value["diagnostics"]["failure_class"], "KNOWN_PRE_SEND_FAILURE")
            self.assertFalse(value["diagnostics"]["send_boundary_reached"])
            self.assertFalse(value["diagnostics"]["reconciliation_required"])
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT state FROM max_provider_dispatch_attempt_current").fetchone()[0], "cancelled")
            self.assertEqual(connection.execute("SELECT state FROM max_provider_call_claim_current").fetchone()[0], "released")
            self.assertEqual(connection.execute("SELECT status FROM max_runner_call_group_current").fetchone()[0], "aborted")
            self.assertEqual(connection.execute("SELECT status FROM max_iteration_outcomes").fetchone()[0], "aborted")
            self.assertEqual(connection.execute("SELECT status FROM max_runner_attempt_outcomes").fetchone()[0], "aborted")
            self.assertIsNone(connection.execute("SELECT 1 FROM max_runner_plan_current").fetchone())
            model_result = connection.execute("SELECT result_status, result_json, usage_json FROM max_model_call_results").fetchone()
            self.assertEqual(model_result[0], "failed")
            durable_result = json.loads(model_result[1])
            self.assertFalse(durable_result["dispatch_known"])
            self.assertEqual(durable_result["provider_call_id"], "not-sent")
            self.assertEqual(json.loads(model_result[2]), {})
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_usage_attestations").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_events WHERE event_type='runner_pre_send_abort_closed'").fetchone()[0], 1)
        idempotent = RunnerPersistence(self.repo).abort_pre_send(
            run_id=self.run_id,
            logical_call_id=self.intent.logical_call_id,
            actor=self.worker,
            fencing_token=self.fencing_token,
            failure_stage="mark_send_started",
            error_code="LIVE_CANARY_PRE_SEND_ABORT",
        )
        self.assertTrue(idempotent["idempotent"])
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_iteration_outcomes").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_events WHERE event_type='runner_pre_send_abort_closed'").fetchone()[0], 1)
        self.assertTrue(self.store.verify(run_id=self.run_id)["ok"])

    def test_dispatch_prepare_failure_closes_runner_before_pause(self) -> None:
        fake, error = self._run_dispatch_stage_fault("dispatch_prepare")
        self.assertEqual(fake.calls, 0)
        self.assertIn("KNOWN_PRE_SEND_FAILURE", str(error))
        self._assert_pre_send_runner_closed()

    def test_dispatch_start_failure_closes_runner_before_pause(self) -> None:
        fake, error = self._run_dispatch_stage_fault("dispatch_start")
        self.assertEqual(fake.calls, 0)
        self.assertIn("KNOWN_PRE_SEND_FAILURE", str(error))
        self._assert_pre_send_runner_closed()

    def test_mark_send_started_after_is_unknown_and_reservation_is_retained(self) -> None:
        _executor, fake, error = self._run_executor_fault(mark_after=True)
        self.assertIn("UNKNOWN_AFTER_SEND", str(error))
        self.assertEqual(fake.calls, 0)
        with closing(self.repo._connect(read_only=True)) as connection:
            outcome = connection.execute("SELECT permit_id, outcome_json FROM max_live_canary_outcomes ORDER BY created_at DESC LIMIT 1").fetchone()
            value = json.loads(outcome[1])
            self.assertEqual(value["outcome"], "unknown")
            self.assertEqual(value["diagnostics"]["failure_class"], "UNKNOWN_AFTER_SEND")
            self.assertTrue(value["diagnostics"]["send_boundary_reached"])
            self.assertTrue(value["diagnostics"]["reconciliation_required"])
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT state FROM max_provider_dispatch_attempt_current").fetchone()[0], "unknown")
            self.assertEqual(connection.execute("SELECT state FROM max_provider_call_claim_current").fetchone()[0], "unknown")
            usage = json.loads(connection.execute("SELECT current_json FROM max_provider_grant_usage_current").fetchone()[0])
            self.assertGreater(usage["reserved_cost_units"], 0)
        self.assertTrue(self.store.verify(run_id=self.run_id)["ok"])

    def test_source_permit_consume_failure_is_known_pre_send(self) -> None:
        preview, inputs, registration = self._execution_inputs()
        fake = _CountingTransport()
        executor = LiveCanaryExecutor(self.repo, self.authority, provider_store=self.store, transport=fake, live_network_enabled=True)
        original = self.authority.consume_source_permit

        def injected(**_kwargs):
            raise LiveCanaryAuthorityError("injected source permit consume failure")

        self.authority.consume_source_permit = injected  # type: ignore[method-assign]
        try:
            with self.assertRaises(LiveCanaryAuthorityError) as caught:
                executor.execute_fixture(
                    authority_id=registration["authority_id"], approval_id=inputs["approval"]["approval_id"], preview_hash=preview["preview_hash"], confirmation_phrase=preview["confirmation_phrase"], actor=self.worker,
                    worker_id=self.worker.actor_id, worker_session=self.worker.session_id, fencing_token=self.fencing_token, claim_id=self.claim_id,
                    request={"phase": "offline-fixture"}, logical_call_id=self.intent.logical_call_id, idempotency_key=self.intent.idempotency_key,
                    authorization_id=inputs["authorization"]["authorization_id"], grant_id=inputs["grant"]["grant_id"], source_permit_validator=lambda: True, allow_execute=True,
                )
        finally:
            self.authority.consume_source_permit = original  # type: ignore[method-assign]
        self.assertIn("KNOWN_PRE_SEND_FAILURE", str(caught.exception))
        self.assertEqual(fake.calls, 0)
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT state FROM max_live_canary_source_permit_current").fetchone()[0], "revoked")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT state FROM max_provider_dispatch_attempt_current").fetchone()[0], "cancelled")
            self.assertEqual(connection.execute("SELECT state FROM max_provider_call_claim_current").fetchone()[0], "released")
            self.assertEqual(connection.execute("SELECT status FROM max_runs").fetchone()[0], "PAUSED")
            self.assertIsNotNone(connection.execute("SELECT released_at FROM max_leases").fetchone()[0])
            closure = connection.execute("SELECT terminal_state, failure_stage, error_code, usage_json, reservation_json, cost_units FROM max_live_execution_grant_closures").fetchone()
            self.assertIsNotNone(closure)
            self.assertEqual(closure[0], "terminal-unused/pre-send-aborted")
            self.assertEqual(closure[1], "source_permit_consume")
            self.assertTrue(closure[2])
            self.assertEqual(json.loads(closure[3])["settled_cost_units"], 0)
            self.assertEqual(json.loads(closure[4])["cost_units"], 0)
            self.assertEqual(closure[5], 0)
        self.assertTrue(self.store.verify(run_id=self.run_id)["ok"])

    def test_transport_send_failure_after_boundary_is_unknown_without_duplicate_call(self) -> None:
        preview, inputs, registration = self._execution_inputs()
        fake = _CountingTransport(raise_on_send=True)
        executor = LiveCanaryExecutor(self.repo, self.authority, provider_store=self.store, transport=fake, live_network_enabled=True)
        with self.assertRaises(LiveCanaryAuthorityError) as caught:
            executor.execute_fixture(
                authority_id=registration["authority_id"], approval_id=inputs["approval"]["approval_id"], preview_hash=preview["preview_hash"], confirmation_phrase=preview["confirmation_phrase"], actor=self.worker,
                worker_id=self.worker.actor_id, worker_session=self.worker.session_id, fencing_token=self.fencing_token, claim_id=self.claim_id,
                request={"phase": "offline-fixture"}, logical_call_id=self.intent.logical_call_id, idempotency_key=self.intent.idempotency_key,
                authorization_id=inputs["authorization"]["authorization_id"], grant_id=inputs["grant"]["grant_id"], source_permit_validator=lambda: True, allow_execute=True,
            )
        self.assertIn("UNKNOWN_AFTER_SEND", str(caught.exception))
        self.assertEqual(fake.calls, 1)
        with closing(self.repo._connect(read_only=True)) as connection:
            outcome = json.loads(connection.execute("SELECT outcome_json FROM max_live_canary_outcomes ORDER BY created_at DESC LIMIT 1").fetchone()[0])
            self.assertEqual(outcome["outcome"], "unknown")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT state FROM max_provider_dispatch_attempt_current").fetchone()[0], "unknown")
        self.assertTrue(self.store.verify(run_id=self.run_id)["ok"])


if __name__ == "__main__":
    unittest.main()
