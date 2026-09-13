from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from research_kb.max_research.contract import RolePacket, model_to_dict
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository
from research_kb.max_research.provider import (
    InjectedCredentialResolver,
    InjectedDNSResolver,
    InjectedHTTPSConnector,
    LiveDispatchPermit,
    LiveOpenAICompatibleAdapter,
    LiveProviderTransportFactory,
    OpenAICompatibleHTTPSLiveTransport,
    ProviderProfile,
    ProviderStore,
    ProviderTransportError,
    TransportResponse,
    default_live_transport,
    network_policy_hash,
)
from research_kb.max_research.runner import InferenceProfile, ModelRequestEnvelope
from research_kb.max_research.scheduler import provider_runner_profile
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.runner.contracts import ModelCallIntent, RunnerPlan
from research_kb.max_research.runner.planner import build_plan
from research_kb.max_research.contract import ResearchState
from research_kb.policy import Actor


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            return self.value

    def advance(self, seconds: int) -> None:
        with self.lock:
            self.value += timedelta(seconds=seconds)


def _policy() -> dict:
    return {"policy_version": "mr2b1/v1"}


def _credential_fixture() -> tuple[str, str]:
    return "MR2B1A_" + "FIXTURE", "offline-" + "injected-" + "value"


def _profile_mapping() -> dict:
    name, _ = _credential_fixture()
    return {
        "profile_id": "mr2b1a-live-profile", "profile_version": "1",
        "protocol": "openai-compatible/v1", "provider_name": "provider-placeholder",
        "model_identity": "model-placeholder/v1", "endpoint_origin": "https://provider.invalid",
        "endpoint_path_policy": "/v1/chat/completions",
        "capabilities": {"structured_json": True, "idempotency": True, "result_query": False, "usage_reporting": True},
        "inference_defaults": {"temperature": 0, "top_p": 1, "max_output_tokens": 32},
        "timeout_policy": {"connect_ms": 1000, "write_ms": 1000, "read_ms": 1000, "total_ms": 5000},
        "retry_policy": {"max_attempts": 1, "backoff_ms": 1, "retry_statuses": [429]},
        "request_limits": {"max_request_bytes": 100000, "max_response_bytes": 100000, "max_prompt_chars": 10000, "max_json_depth": 12, "max_input_tokens": 512, "max_output_tokens": 32, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0},
        "rate_policy": {"max_concurrency": 1, "per_minute": 60},
        "credential_ref": {"kind": "environment", "name": name},
        "network_policy_hash": network_policy_hash(_policy()),
        "pricing": {"pricing_id": "mr2b1a-price", "pricing_version": "1", "currency": "USD", "unit": "cost_units", "input_per_1k": "1", "output_per_1k": "2", "cache_per_1k": "0", "reasoning_per_1k": "0", "effective_at": "2026-01-01T00:00:00.000Z", "source_label": "offline-fixture"},
    }


class MR2B1ATests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr2b1a-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("mr2b1a-admin", "mr2b1a-admin-session", "user", "admin", "mr2b1a-tests")
        self.worker = Actor("mr2b1a-worker", "mr2b1a-worker-session", "worker", "runner", "mr2b1a-tests")
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize()
        self.store = ProviderStore(self.repo)
        registered = self.store.register_profile(profile=ProviderProfile.from_mapping(_profile_mapping()), actor=self.admin)
        self.profile = self.store.get_profile(profile_hash=registered["profile_hash"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _run_grant_auth(self, *, ttl_seconds: int = 3600) -> tuple[str, dict, dict]:
        charter = {"question": f"offline permit {uuid.uuid4().hex}", "scope": "MR-2B1A", "invariants": ["permit authority"], "non_goals": ["network"], "deliverables": ["audit"], "model_identity": self.profile.model_identity, "budget": {"iteration_count": 2, "input_tokens": 10000, "output_tokens": 10000, "cost_units": 1000}, "source_policy": {"network_allowed": False, "roles": ["primary"]}, "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]}}
        proposed = self.repo.propose(project_id="mr2b1a-project", charter=charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="offline fixture", actor=self.admin)
        started = self.repo.start(run_id=proposed["run_id"], actor=self.admin, lease_ttl=300)
        self.store.bind_run_profile(run_id=proposed["run_id"], profile_hash=self.profile.profile_hash, actor=self.admin)
        grant = self.store.issue_live_execution_grant(run_id=proposed["run_id"], profile_hash=self.profile.profile_hash, caps={"max_ticks": 2, "max_iterations": 2, "max_wall_clock_seconds": 1000, "max_consecutive_failures": 2, "max_no_progress": 10, "max_provider_calls": 1, "max_input_tokens": 10000, "max_output_tokens": 10000, "max_cost_units": 1000}, reason="offline grant", actor=self.admin)
        binding = self.store.get_run_binding(run_id=proposed["run_id"])
        self.store.consume_execution_grant(grant_id=grant["grant_id"], run_id=proposed["run_id"], project_id="mr2b1a-project", profile_hash=self.profile.profile_hash, model_identity=self.profile.model_identity, network_policy_hash=self.profile.network_policy_hash, pricing_hash=self.profile.pricing.pricing_hash, budget_hash=binding["budget_hash"], consumer=self.admin)
        maximum = self.profile.pricing.cost_units_for_usage(self.profile.authority_maximum_usage())
        auth = self.store.issue_live_network_authorization(run_id=proposed["run_id"], grant_id=grant["grant_id"], caps={"max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": maximum}, network_policy=_policy(), reason="offline permit boundary", actor=self.admin, ttl_seconds=ttl_seconds)
        runner_profile = provider_runner_profile(self.profile)
        runner_persistence = RunnerPersistence(self.repo)
        runner_persistence.register_profile(profile=runner_profile, actor=self.admin)
        handoff = runner_persistence.handoff_runner(run_id=proposed["run_id"], profile=runner_profile, admin_actor=self.admin, runner_actor=self.worker, admin_fencing_token=int(started["lease"]["fencing_token"]), lease_ttl=300)
        return proposed["run_id"], grant, {**auth, "fencing_token": handoff["lease"]["fencing_token"]}

    def _prepare_intent(self, run_id: str, grant: dict, auth: dict, *, logical_call_id: str = "mr2b1a-logical-call", idempotency_key: str = "mr2b1a-idempotency") -> tuple[ModelRequestEnvelope, int]:
        runner_profile = provider_runner_profile(self.profile)
        persistence = RunnerPersistence(self.repo)
        persistence.register_profile(profile=runner_profile, actor=self.admin)
        state = ResearchState.from_mapping(self.repo.get_state(run_id=run_id))
        plan = build_plan(project_id="mr2b1a-project", run_id=run_id, sequence=1, state=model_to_dict(state), history=(), profile=runner_profile)
        fence = int(auth["fencing_token"])
        persistence.register_profile(profile=runner_profile, actor=self.admin)
        self.repo.begin_iteration(run_id=run_id, round_type=plan.round_type, actor=self.worker, fencing_token=fence, input_state_hash=plan.input_state_hash, iteration_id=plan.iteration_id, requested_sequence=1)
        persistence.record_plan(run_id=run_id, plan=plan, profile=runner_profile, actor=self.worker, fencing_token=fence)
        persistence.bind_plan(run_id=run_id, plan_id=plan.plan_id, iteration_id=plan.iteration_id, actor=self.worker, fencing_token=fence)
        group = persistence.record_call_group(run_id=run_id, plan=plan, actor=self.worker, fencing_token=fence)
        packet = plan.role_packets[0]
        request = ModelRequestEnvelope(project_id="mr2b1a-project", run_id=run_id, iteration_id=plan.iteration_id, role_packet=packet, model_identity=self.profile.model_identity, inference_profile=InferenceProfile(max_output_tokens=32, timeout_seconds=5), context={"provider_profile_hash": self.profile.profile_hash, "gateway_name": "offline", "canonical_ids": []}, request_payload={"phase": "exploration", "logical_call_id": logical_call_id})
        intent = ModelCallIntent(project_id="mr2b1a-project", run_id=run_id, iteration_id=plan.iteration_id, input_state_hash=plan.input_state_hash, role_packet_id=packet.packet_id, round_type=plan.round_type, model_identity=self.profile.model_identity, inference_profile_hash=runner_profile.inference_profile.inference_profile_hash, request_hash=request.request_hash, idempotency_key=idempotency_key, request=request, logical_call_id=logical_call_id)
        persistence.record_intent(run_id=run_id, intent=intent, plan_id=plan.plan_id, actor=self.worker, fencing_token=fence, group_id=group["group_id"], call_index=0, phase=plan.call_specs[0].phase)
        return intent.request, fence

    def _transport(self, permit: LiveDispatchPermit, *, response: TransportResponse | None = None, dns=None, resolver=None, connector=None):
        name, value = _credential_fixture()
        resolver = resolver or InjectedCredentialResolver({name: value})
        dns = dns or InjectedDNSResolver({"provider.invalid": ["93.184.216.34"]})
        connector = connector or InjectedHTTPSConnector(response or TransportResponse(200, b"{}", {"content-type": "application/json"}, "fixture-call", True))
        return OpenAICompatibleHTTPSLiveTransport(endpoint_origin=self.profile.endpoint_origin, endpoint_path_policy=self.profile.endpoint_path_policy, credential_ref=self.profile.credential_ref, network_policy=_policy(), credential_resolver=resolver, permit=permit, permit_validator=self.store.validate_live_dispatch_permit, dns_resolver=dns, connector=connector), resolver, dns, connector

    def _started_permit(self) -> tuple[LiveDispatchPermit, ModelRequestEnvelope, bytes, int, str]:
        run_id, grant, auth = self._run_grant_auth()
        suffix = uuid.uuid4().hex
        logical_call_id = f"mr2b1a-logical-call-{suffix}"
        idempotency_key = f"mr2b1a-idempotency-{suffix}"
        request, fence = self._prepare_intent(run_id, grant, auth, logical_call_id=logical_call_id, idempotency_key=idempotency_key)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        prepared = self.store.prepare_live_dispatch(
            authorization_id=auth["authorization_id"], run_id=run_id,
            project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile,
            request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(),
            intent_hash=request.intent_hash, logical_call_id=logical_call_id,
            idempotency_key=idempotency_key, actor=self.worker, fencing_token=fence,
        )
        started = self.store.start_live_dispatch(permit=prepared["permit"], actor=self.worker, fencing_token=fence)
        return started, request, encoded.body, fence, idempotency_key

    def test_empty_and_schema9_upgrade_are_schema10_and_core_independent(self) -> None:
        self.assertEqual(self.repo.verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT MAX(version) FROM max_schema_migrations").fetchone()[0], CONTROL_SCHEMA_VERSION)
            self.assertIn("max_live_dispatch_permits", {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")})
            self.assertNotIn("research_documents", {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")})

    def test_prepare_is_atomic_and_busy_losers_do_not_consume_authorization(self) -> None:
        run_id, grant, auth = self._run_grant_auth()
        request, fence = self._prepare_intent(run_id, grant, auth)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        def prepare(index: int):
            worker = self.worker if index == 0 else Actor(f"loser-{index}", f"loser-session-{index}", "worker", "runner", "mr2b1a-tests")
            try:
                return self.store.prepare_live_dispatch(authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile, request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(), intent_hash=request.intent_hash, logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency", actor=worker, fencing_token=fence)
            except Exception as exc:
                return exc
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(prepare, range(20)))
        successes = [result for result in results if isinstance(result, dict) and not result.get("idempotent")]
        self.assertEqual(len(successes), 1)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_network_authorization_consumptions").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_dispatch_permits").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT state FROM max_live_network_authorization_current WHERE authorization_id=?", (auth["authorization_id"],)).fetchone()[0], "consumed")

    def test_forged_boolean_gate_and_forged_permit_are_rejected_before_io(self) -> None:
        with self.assertRaises(TypeError):
            OpenAICompatibleHTTPSLiveTransport(endpoint_origin=self.profile.endpoint_origin, endpoint_path_policy=self.profile.endpoint_path_policy, credential_ref=self.profile.credential_ref, network_policy=_policy(), credential_resolver=InjectedCredentialResolver({}), authorization_checked=True, attempt_persisted=True)  # type: ignore[call-arg]
        with self.assertRaises(Exception):
            LiveDispatchPermit.from_mapping({})
        run_id, grant, auth = self._run_grant_auth()
        request, fence = self._prepare_intent(run_id, grant, auth)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        prepared = self.store.prepare_live_dispatch(authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile, request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(), intent_hash=request.intent_hash, logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency", actor=self.worker, fencing_token=fence)
        permit = prepared["permit"]
        transport, resolver, dns, connector = self._transport(permit)
        with self.assertRaises(ProviderTransportError):
            transport.send(encoded.body, headers={"Content-Type": "application/json"}, timeout_ms=1000, idempotency_key="wrong")
        self.assertEqual(resolver.read_count, 0); self.assertEqual(dns.lookup_count, 0); self.assertEqual(connector.network_call_count, 0)

    def test_start_send_and_settled_replay_have_one_physical_call(self) -> None:
        run_id, grant, auth = self._run_grant_auth()
        request, fence = self._prepare_intent(run_id, grant, auth)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        prepared = self.store.prepare_live_dispatch(authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile, request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(), intent_hash=request.intent_hash, logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency", actor=self.worker, fencing_token=fence)
        permit = self.store.start_live_dispatch(permit=prepared["permit"], actor=self.worker, fencing_token=fence)
        response_body = b'{"id":"fixture-call","object":"chat.completion","model":"model-placeholder/v1","choices":[{"message":{"role":"assistant","content":"{}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}'
        transport, resolver, dns, connector = self._transport(permit, response=TransportResponse(200, response_body, {"content-type": "application/json"}, "fixture-call", True))
        output = transport.send(encoded.body, headers={"Content-Type": "application/json"}, timeout_ms=1000, idempotency_key="mr2b1a-idempotency")
        self.assertEqual(output.status_code, 200); self.assertEqual(connector.network_call_count, 1); self.assertEqual(resolver.read_count, 1); self.assertEqual(dns.lookup_count, 1)
        self.store.mark_live_dispatch_outcome(permit=permit, state="settled", actor=self.worker, details={"response_hash": hashlib.sha256(response_body).hexdigest()})
        second = self.store.prepare_live_dispatch(authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile, request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(), intent_hash=request.intent_hash, logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency", actor=self.worker, fencing_token=fence)
        self.assertTrue(second["idempotent"]); self.assertEqual(self.store.verify_live_network(run_id=run_id)["counts"]["permits"], 1)

    def test_revoke_expire_and_stale_or_cross_run_permit_fail_closed(self) -> None:
        run_id, grant, auth = self._run_grant_auth()
        self.assertEqual(self.store.revoke_live_network_authorization(authorization_id=auth["authorization_id"], actor=self.admin, reason="manual offline revoke")["state"], "revoked")
        request, fence = self._prepare_intent(run_id, grant, auth)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        with self.assertRaises(MaxControlError):
            self.store.prepare_live_dispatch(authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile, request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(), intent_hash=request.intent_hash, logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency", actor=self.admin, fencing_token=fence)
        repeated = self.store.revoke_live_network_authorization(authorization_id=auth["authorization_id"], actor=self.admin, reason="restore attempt")
        self.assertTrue(repeated["idempotent"])

    def test_expire_is_admin_only_and_rejects_before_deadline(self) -> None:
        clock = FakeClock()
        self.repo.clock = clock
        run_id, _grant, auth = self._run_grant_auth(ttl_seconds=2)
        with self.assertRaises(MaxControlError):
            self.store.expire_live_network_authorization(authorization_id=auth["authorization_id"], actor=self.admin, reason="too early")
        clock.advance(3)
        expired = self.store.expire_live_network_authorization(authorization_id=auth["authorization_id"], actor=self.admin, reason="offline expiry")
        self.assertEqual(expired["state"], "expired")
        with self.assertRaises(MaxControlError):
            self.store.consume_live_network_authorization(
                authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project",
                grant_id=_grant["grant_id"], profile_hash=self.profile.profile_hash,
                provider_name=self.profile.provider_name, model_identity=self.profile.model_identity,
                endpoint_origin=self.profile.endpoint_origin, endpoint_path_policy=self.profile.endpoint_path_policy,
                credential_ref=self.profile.credential_ref, consumer=self.worker,
            )
        self.assertEqual(self.store.live_authorization_status(run_id=run_id)["authorizations"][0]["state"], "expired")

    def test_revoke_consume_race_has_one_terminal_winner_for_twenty_rounds(self) -> None:
        outcomes = []
        for index in range(20):
            run_id, grant, auth = self._run_grant_auth()
            consume_kwargs = {
                "authorization_id": auth["authorization_id"], "run_id": run_id, "project_id": "mr2b1a-project",
                "grant_id": grant["grant_id"], "profile_hash": self.profile.profile_hash,
                "provider_name": self.profile.provider_name, "model_identity": self.profile.model_identity,
                "endpoint_origin": self.profile.endpoint_origin, "endpoint_path_policy": self.profile.endpoint_path_policy,
                "credential_ref": self.profile.credential_ref, "consumer": self.worker,
                "fencing_token": auth["fencing_token"],
            }
            barrier = threading.Barrier(2)

            def consume() -> str:
                barrier.wait()
                try:
                    self.store.consume_live_network_authorization(**consume_kwargs)
                    return "consumed"
                except Exception:
                    return "rejected"

            def revoke() -> str:
                barrier.wait()
                try:
                    self.store.revoke_live_network_authorization(authorization_id=auth["authorization_id"], actor=self.admin, reason=f"race {index}")
                    return "revoked"
                except Exception:
                    return "rejected"

            with ThreadPoolExecutor(max_workers=2) as pool:
                result = list(pool.map(lambda fn: fn(), (consume, revoke)))
            state = self.store.live_authorization_status(run_id=run_id)["authorizations"][0]["state"]
            self.assertIn(state, {"consumed", "revoked"})
            self.assertEqual(sum(value in {"consumed", "revoked"} for value in result), 1)
            outcomes.append(state)
        self.assertEqual(len(outcomes), 20)

    def test_prepared_crash_reuses_one_permit_and_send_started_crash_is_unknown(self) -> None:
        run_id, grant, auth = self._run_grant_auth()
        request, fence = self._prepare_intent(run_id, grant, auth)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        prepared = self.store.prepare_live_dispatch(
            authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"],
            profile=self.profile, request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(),
            intent_hash=request.intent_hash, logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency",
            actor=self.worker, fencing_token=fence,
        )
        self.assertEqual(self.store.live_authorization_status(run_id=run_id)["authorizations"][0]["state"], "consumed")
        reopened = ProviderStore(MaxControlRepository(self.path))
        replayed = reopened.prepare_live_dispatch(
            authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"],
            profile=self.profile, request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(),
            intent_hash=request.intent_hash, logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency",
            actor=self.worker, fencing_token=fence,
        )
        self.assertTrue(replayed["idempotent"])
        self.assertEqual(replayed["permit"].permit_id, prepared["permit"].permit_id)
        started = reopened.start_live_dispatch(permit=replayed["permit"], actor=self.worker, fencing_token=fence)
        reopened.mark_live_dispatch_outcome(permit=started, state="unknown", actor=self.worker, details={"code": "CRASH_AFTER_SEND_START"})
        with self.assertRaises(MaxControlError):
            reopened.prepare_live_dispatch(
                authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"],
                profile=self.profile, request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(),
                intent_hash=request.intent_hash, logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency",
                actor=self.worker, fencing_token=fence,
            )
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_dispatch_permits").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT state FROM max_live_dispatch_permit_current").fetchone()[0], "unknown")

    def test_production_factory_accepts_only_registered_run_bound_permit(self) -> None:
        with self.assertRaises(ProviderTransportError):
            LiveProviderTransportFactory.create_for_permit(profile=self.profile, permit=object(), provider_store=self.store)
        run_id, grant, auth = self._run_grant_auth()
        request, fence = self._prepare_intent(run_id, grant, auth)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        prepared = self.store.prepare_live_dispatch(
            authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile,
            request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(), intent_hash=request.intent_hash,
            logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency", actor=self.worker, fencing_token=fence,
        )
        started = self.store.start_live_dispatch(permit=prepared["permit"], actor=self.worker, fencing_token=fence)
        transport = LiveProviderTransportFactory.create_for_permit(profile=self.profile, permit=started, provider_store=self.store)
        self.assertEqual(transport.network_call_count, 0)
        self.assertEqual(transport.credential_read_count, 0)
        self.assertEqual(transport.dns_lookup_count, 0)
        with self.assertRaises(ProviderTransportError):
            LiveProviderTransportFactory.create_for_permit(profile=self.profile, permit=started, provider_store=object())

    def test_permit_event_and_column_tampering_is_detected(self) -> None:
        run_id, grant, auth = self._run_grant_auth()
        request, fence = self._prepare_intent(run_id, grant, auth)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        prepared = self.store.prepare_live_dispatch(
            authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile,
            request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(), intent_hash=request.intent_hash,
            logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency", actor=self.worker, fencing_token=fence,
        )
        tampered = Path(self.temp.name) / "permit-tampered.db"
        with closing(sqlite3.connect(self.path)) as source, closing(sqlite3.connect(tampered)) as target:
            source.backup(target)
        with closing(sqlite3.connect(tampered)) as db:
            db.execute("DROP TRIGGER max_live_dispatch_permits_no_update")
            db.execute("UPDATE max_live_dispatch_permits SET provider_name='tampered' WHERE permit_id=?", (prepared["permit"].permit_id,))
            db.commit()
        self.assertFalse(ProviderStore(MaxControlRepository(tampered)).verify_live_network(run_id=run_id)["ok"])

    def test_stale_outcome_fence_is_rejected_before_audit_write(self) -> None:
        clock = FakeClock()
        self.repo.clock = clock
        run_id, grant, auth = self._run_grant_auth()
        request, fence = self._prepare_intent(run_id, grant, auth)
        from research_kb.max_research.provider.codec import OpenAICompatibleCodec
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        prepared = self.store.prepare_live_dispatch(
            authorization_id=auth["authorization_id"], run_id=run_id, project_id="mr2b1a-project", grant_id=grant["grant_id"], profile=self.profile,
            request_hash=request.request_hash, wire_request_hash=hashlib.sha256(encoded.body).hexdigest(), intent_hash=request.intent_hash,
            logical_call_id="mr2b1a-logical-call", idempotency_key="mr2b1a-idempotency", actor=self.worker, fencing_token=fence,
        )
        started = self.store.start_live_dispatch(permit=prepared["permit"], actor=self.worker, fencing_token=fence)
        clock.advance(301)
        takeover = Actor("mr2b1a-takeover", "mr2b1a-takeover-session", "worker", "runner", "mr2b1a-tests")
        self.repo.acquire_lease(run_id=run_id, actor=takeover, ttl_seconds=300)
        with self.assertRaises(MaxControlError):
            self.store.mark_live_dispatch_outcome(permit=started, state="unknown", actor=self.worker, details={"code": "STALE"})
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT state FROM max_live_dispatch_permit_current WHERE permit_id=?", (started.permit_id,)).fetchone()[0], "send_started")

    def test_dns_candidates_and_size_limits_fail_before_credential_or_network(self) -> None:
        permit, _request, body, _fence, idempotency_key = self._started_permit()
        name, value = _credential_fixture()
        resolver = InjectedCredentialResolver({name: value})
        connector = InjectedHTTPSConnector()
        dns = InjectedDNSResolver({"provider.invalid": ["93.184.216.34", "127.0.0.1"]})
        transport = OpenAICompatibleHTTPSLiveTransport(
            endpoint_origin=self.profile.endpoint_origin,
            endpoint_path_policy=self.profile.endpoint_path_policy,
            credential_ref=self.profile.credential_ref,
            network_policy=_policy(), credential_resolver=resolver, permit=permit,
            permit_validator=self.store.validate_live_dispatch_permit,
            dns_resolver=dns, connector=connector,
        )
        with self.assertRaises(ProviderTransportError) as blocked:
            transport.send(body, headers={"Content-Type": "application/json"}, timeout_ms=1000, idempotency_key=idempotency_key)
        self.assertEqual(blocked.exception.code, "SSRF_ADDRESS_BLOCKED")
        self.assertEqual(resolver.read_count, 0)
        self.assertEqual(connector.network_call_count, 0)

        permit2, _request2, body2, _fence2, idempotency_key2 = self._started_permit()
        resolver2 = InjectedCredentialResolver({name: value})
        dns2 = InjectedDNSResolver({"provider.invalid": ["93.184.216.34"]})
        connector2 = InjectedHTTPSConnector()
        transport2 = OpenAICompatibleHTTPSLiveTransport(
            endpoint_origin=self.profile.endpoint_origin,
            endpoint_path_policy=self.profile.endpoint_path_policy,
            credential_ref=self.profile.credential_ref,
            network_policy={**_policy(), "max_request_bytes": len(body2) - 1},
            credential_resolver=resolver2, permit=permit2,
            permit_validator=self.store.validate_live_dispatch_permit,
            dns_resolver=dns2, connector=connector2,
        )
        with self.assertRaises(ProviderTransportError) as too_large:
            transport2.send(body2, headers={"Content-Type": "application/json"}, timeout_ms=1000, idempotency_key=idempotency_key2)
        self.assertEqual(too_large.exception.code, "REQUEST_TOO_LARGE")
        self.assertEqual(resolver2.read_count, 0)
        self.assertEqual(dns2.lookup_count, 0)
        self.assertEqual(connector2.network_call_count, 0)

    def test_timeout_redirect_and_fixture_transcript_do_not_leak_credential(self) -> None:
        permit, _request, body, _fence, idempotency_key = self._started_permit()
        name, credential_value = _credential_fixture()
        resolver = InjectedCredentialResolver({name: credential_value})
        connector = InjectedHTTPSConnector(error=TimeoutError("fixture timeout"))
        transport, _resolver, _dns, _connector = self._transport(permit, resolver=resolver, connector=connector)
        with self.assertRaises(ProviderTransportError) as timeout:
            transport.send(body, headers={"Content-Type": "application/json"}, timeout_ms=1000, idempotency_key=idempotency_key)
        self.assertEqual(timeout.exception.code, "PROVIDER_TIMEOUT")
        self.assertFalse(credential_value in repr(connector.requests))
        self.assertEqual(connector.network_call_count, 1)

        permit2, _request2, body2, _fence2, idempotency_key2 = self._started_permit()
        resolver2 = InjectedCredentialResolver({name: credential_value})
        connector2 = InjectedHTTPSConnector(TransportResponse(302, b"redirect", {"location": "https://other.invalid"}, "redirect", True))
        transport2, _resolver2, _dns2, _connector2 = self._transport(permit2, resolver=resolver2, connector=connector2)
        with self.assertRaises(ProviderTransportError) as redirect:
            transport2.send(body2, headers={"Content-Type": "application/json"}, timeout_ms=1000, idempotency_key=idempotency_key2)
        self.assertEqual(redirect.exception.code, "REDIRECT_FORBIDDEN")
        self.assertEqual(connector2.network_call_count, 1)
        self.assertFalse(credential_value in repr(connector2.requests))

    def test_backup_restore_and_default_factory_are_offline(self) -> None:
        run_id, _grant, auth = self._run_grant_auth()
        backup = Path(self.temp.name) / "backup.db"
        restored = Path(self.temp.name) / "restored.db"
        self.repo.backup(backup); MaxControlRepository(restored).restore(backup)
        self.assertTrue(ProviderStore(MaxControlRepository(restored)).verify_live_network(run_id=run_id)["ok"])
        disabled = default_live_transport()
        with self.assertRaises(ProviderTransportError):
            disabled.send(b"{}", headers={}, timeout_ms=1000, idempotency_key="offline")
        self.assertEqual(disabled.network_call_count, 0); self.assertEqual(disabled.credential_read_count, 0)


if __name__ == "__main__":
    unittest.main()
