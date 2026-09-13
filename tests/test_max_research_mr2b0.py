from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from research_kb.max_research.contract import RolePacket, canonical_sha256
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository
from research_kb.max_research.provider import (
    DisabledLiveTransport,
    HermeticTransport,
    OpenAICompatibleAdapter,
    OpenAICompatibleCodec,
    PricingSnapshot,
    ProviderProfile,
    ProviderStore,
    ProviderTransportError,
    ProviderUsageAuthority,
    TransportResponse,
)
from research_kb.max_research.runner import BoundedRunner, InferenceProfile, ModelRequestEnvelope
from research_kb.max_research.scheduler import ForegroundScheduler, HermeticResearchGateway, SchedulerPolicy, provider_runner_profile
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.policy import Actor


def profile_mapping(model: str = "hermetic-model/v1") -> dict:
    return {
        "profile_id": "hermetic-profile",
        "profile_version": "1",
        "protocol": "openai-compatible/v1",
        "provider_name": "hermetic-provider",
        "model_identity": model,
        "endpoint_origin": "https://provider.invalid",
        "endpoint_path_policy": "/v1/chat/completions",
        "capabilities": {"structured_json": True, "idempotency": True, "result_query": True, "usage_reporting": True},
        "inference_defaults": {"temperature": 0, "top_p": 1, "max_output_tokens": 128, "seed": 0},
        "timeout_policy": {"connect_ms": 1000, "write_ms": 1000, "read_ms": 1000, "total_ms": 5000},
        "retry_policy": {"max_attempts": 1, "backoff_ms": 1, "retry_statuses": [429]},
        "request_limits": {"max_request_bytes": 100000, "max_response_bytes": 100000, "max_prompt_chars": 10000, "max_json_depth": 12, "max_input_tokens": 2500, "max_output_tokens": 128, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0},
        "rate_policy": {"max_concurrency": 1, "per_minute": 60},
        "credential_ref": {"kind": "injected", "name": "hermetic-fixture"},
        "network_policy_hash": "a" * 64,
        "pricing": {"pricing_id": "hermetic-price", "pricing_version": "1", "currency": "USD", "unit": "cost_units", "input_per_1k": "1", "output_per_1k": "2", "cache_per_1k": "0", "reasoning_per_1k": "0", "effective_at": "2026-01-01T00:00:00.000Z", "source_label": "test-fixture"},
    }


def response_body(model: str = "hermetic-model/v1", call_id: str = "call-1", *, project_id: str | None = None) -> dict:
    objects = [] if project_id is None else [{"stable_id": f"mr1:hypothesis:{canonical_sha256(call_id)[:48]}", "kind": "hypothesis", "project_id": project_id, "version": 1, "payload": {"label": "hermetic candidate", "status": "candidate"}}]
    proposal = {"objects": objects, "relations": [], "artifact_links": [], "record_refs": [], "strategy": None, "output_summary": "bounded hermetic result", "role_outputs": [], "deliberation": None}
    return {"id": call_id, "object": "chat.completion", "created": 1, "model": model, "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps(proposal, separators=(",", ":"))}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}}


class MR2B0ProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr2b0-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("mr2b0-admin", "mr2b0-admin-session", "user", "admin", "mr2b0-tests")
        self.worker = Actor("mr2b0-worker", "mr2b0-worker-session", "worker", "runner", "mr2b0-tests")
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize()
        self.store = ProviderStore(self.repo)
        candidate = ProviderProfile.from_mapping(profile_mapping())
        registered = self.store.register_profile(profile=candidate, actor=self.admin)
        self.profile = self.store.get_profile(profile_hash=registered["profile_hash"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def prepare_running_run(self, *, iteration_count: int = 10) -> str:
        charter = {
            "question": "Bounded hermetic provider control",
            "scope": "MR-2B0",
            "invariants": ["exact model"],
            "non_goals": ["network"],
            "deliverables": ["audit"],
            "model_identity": self.profile.model_identity,
            "budget": {"iteration_count": iteration_count, "input_tokens": 10000, "output_tokens": 10000, "cost_units": 1000},
            "source_policy": {"network_allowed": False, "roles": ["primary"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        proposed = self.repo.propose(project_id="mr2b0-project", charter=charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="fixture", actor=self.admin)
        self.repo.start(run_id=proposed["run_id"], actor=self.admin, lease_ttl=300)
        self.store.bind_run_profile(run_id=proposed["run_id"], profile_hash=self.profile.profile_hash, actor=self.admin)
        return proposed["run_id"]

    @staticmethod
    def grant_caps(max_ticks: int, *, max_iterations: int | None = None, max_provider_calls: int | None = None, max_consecutive_failures: int = 5, max_no_progress: int = 100, max_wall_clock_seconds: int = 100000) -> dict[str, int]:
        iterations = max_iterations if max_iterations is not None else max_ticks
        return {
            "max_ticks": max_ticks,
            "max_iterations": iterations,
            "max_wall_clock_seconds": max_wall_clock_seconds,
            "max_consecutive_failures": max_consecutive_failures,
            "max_no_progress": max_no_progress,
            "max_provider_calls": max_provider_calls if max_provider_calls is not None else max(10, max_ticks * 5),
            "max_input_tokens": 10000,
            "max_output_tokens": 10000,
            "max_cost_units": 1000,
        }

    def prepare_scheduler_authority(self, run_id: str, policy: SchedulerPolicy, *, worker: Actor | None = None, lease_ttl: int = 300) -> ForegroundScheduler:
        """Perform the explicit admin preparation required before a tick."""

        selected_worker = worker or self.worker
        runner_profile = provider_runner_profile(self.profile)
        persistence = RunnerPersistence(self.repo)
        persistence.register_profile(profile=runner_profile, actor=self.admin)
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            lease = db.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at, runner_profile_hash FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
        if lease is None:
            raise AssertionError("fixture run lease is missing")
        if lease["owner_id"] != selected_worker.actor_id or lease["session_id"] != selected_worker.session_id or lease["runner_profile_hash"] != runner_profile.profile_hash:
            admin_fence = int(lease["fencing_token"]) if lease["owner_id"] == self.admin.actor_id and not lease["released_at"] else None
            persistence.handoff_runner(run_id=run_id, profile=runner_profile, admin_actor=self.admin, runner_actor=selected_worker, admin_fencing_token=admin_fence, lease_ttl=lease_ttl)
        scheduler = ForegroundScheduler(self.repo, selected_worker, provider_store=self.store, admin_actor=self.admin)
        scheduler.persist_policy(policy=policy, actor=self.admin)
        return scheduler

    def test_profile_is_strict_and_live_transport_is_disabled(self) -> None:
        registered = self.store.register_profile(profile=self.profile, actor=self.admin)
        self.assertEqual(registered["profile_hash"], self.profile.profile_hash)
        with self.assertRaises(ProviderTransportError):
            OpenAICompatibleAdapter(self.profile, DisabledLiveTransport())
        with self.assertRaises(ValueError):
            ProviderProfile.from_mapping({**profile_mapping(), "unknown": True})

        for origin in (
            "http://provider.invalid",
            "https://127.0.0.1",
            "https://user:password@provider.invalid",
            "https://provider.invalid?token=forbidden",
            "https://provider.invalid/private/path",
            "https://例.invalid",
        ):
            with self.assertRaises(ValueError, msg=origin):
                ProviderProfile.from_mapping({**profile_mapping(), "endpoint_origin": origin})
        with self.assertRaises(ValueError):
            ProviderProfile.from_mapping({**profile_mapping(), "inference_defaults": {"api_key": "sentinel"}})
        with self.assertRaises(ValueError):
            ProviderProfile.from_mapping({**profile_mapping(), "model_id": "other", "model_identity": "hermetic-model/v1"})

    def test_mr2b0r_closed_transport_complete_caps_and_cost_upper_bound(self) -> None:
        class LiveShapedTransport(HermeticTransport):
            def send(self, request: bytes, *, headers, timeout_ms: int, idempotency_key: str):
                self.network_call_count += 1
                raise AssertionError("live-shaped subclass must never dispatch")

        with self.assertRaises(ProviderTransportError):
            OpenAICompatibleAdapter(self.profile, LiveShapedTransport())

        run_id = self.prepare_running_run()
        with self.assertRaises(MaxControlError):
            self.store.issue_live_execution_grant(run_id=run_id, profile_hash=self.profile.profile_hash, caps={"max_ticks": 1}, reason="tick-only grant must fail", actor=self.admin)
        grant = self.store.issue_live_execution_grant(run_id=run_id, profile_hash=self.profile.profile_hash, caps=self.grant_caps(1), reason="complete bounded grant", actor=self.admin)
        self.assertTrue(grant["grant_id"])
        provider_runner = provider_runner_profile(self.profile)
        self.assertEqual(provider_runner.call_budget["cost_units"], self.profile.pricing.cost_units_for_usage(self.profile.maximum_usage()))
        self.assertGreaterEqual(provider_runner.call_budget["cost_units"], 3)

    def test_grant_caps_expiry_and_replay_are_fail_closed(self) -> None:
        run_id = self.prepare_running_run()
        clock = type(
            "Clock",
            (),
            {
                "value": __import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc),
                "__call__": lambda self: self.value,
                "advance": lambda self, seconds: setattr(self, "value", self.value + __import__("datetime").timedelta(seconds=seconds)),
            },
        )()
        self.repo.clock = clock
        grant = self.store.issue_live_execution_grant(run_id=run_id, profile_hash=self.profile.profile_hash, caps=self.grant_caps(2), reason="explicit hermetic replay fixture", ttl_seconds=1, actor=self.admin)
        binding = self.store.get_run_binding(run_id=run_id)
        first = self.store.consume_execution_grant(grant_id=grant["grant_id"], run_id=run_id, project_id=binding["project_id"], profile_hash=self.profile.profile_hash, model_identity=self.profile.model_identity, network_policy_hash=self.profile.network_policy_hash, pricing_hash=self.profile.pricing.pricing_hash, budget_hash=binding["budget_hash"], consumer=self.worker)
        replay = self.store.consume_execution_grant(grant_id=grant["grant_id"], run_id=run_id, project_id=binding["project_id"], profile_hash=self.profile.profile_hash, model_identity=self.profile.model_identity, network_policy_hash=self.profile.network_policy_hash, pricing_hash=self.profile.pricing.pricing_hash, budget_hash=binding["budget_hash"], consumer=self.worker)
        self.assertEqual(first["consumption_id"], replay["consumption_id"])
        with self.assertRaises(MaxControlError):
            self.store.consume_execution_grant(grant_id=grant["grant_id"], run_id=run_id, project_id=binding["project_id"], profile_hash=self.profile.profile_hash, model_identity=self.profile.model_identity, network_policy_hash=self.profile.network_policy_hash, pricing_hash=self.profile.pricing.pricing_hash, budget_hash=binding["budget_hash"], consumer=Actor("other", "other-session", "worker", "runner", "mr2b0-tests"))
        clock.advance(2)
        self.assertFalse(self.store.grant_status(run_id=run_id)["grants"][0]["active"])

    def test_scheduler_rejects_policy_above_grant_cap(self) -> None:
        run_id = self.prepare_running_run()
        grant = self.store.issue_live_execution_grant(run_id=run_id, profile_hash=self.profile.profile_hash, caps=self.grant_caps(1, max_iterations=1), reason="explicit hermetic cap fixture", actor=self.admin)
        scheduler = ForegroundScheduler(self.repo, self.worker, provider_store=self.store, admin_actor=self.admin)
        with self.assertRaises(MaxControlError):
            scheduler.tick(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=HermeticTransport([TransportResponse(200, response_body(project_id="mr2b0-project"), {}, "cap-call")]), policy=SchedulerPolicy(max_ticks=2, max_iterations=2))

    def test_scheduler_expired_lease_handoff_reuses_one_grant_and_fences_old_worker(self) -> None:
        run_id = self.prepare_running_run(iteration_count=10)
        clock = type(
            "Clock",
            (),
            {
                "value": __import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc),
                "__call__": lambda self: self.value,
                "advance": lambda self, seconds: setattr(self, "value", self.value + __import__("datetime").timedelta(seconds=seconds)),
            },
        )()
        self.repo.clock = clock
        grant = self.store.issue_live_execution_grant(run_id=run_id, profile_hash=self.profile.profile_hash, caps=self.grant_caps(3, max_iterations=3), reason="explicit hermetic handoff fixture", actor=self.admin)

        def handler(request: bytes, _headers, idempotency_key: str):
            wire = json.loads(request.decode("utf-8"))
            return TransportResponse(200, response_body(wire["model"], f"handoff-{idempotency_key}", project_id="mr2b0-project"), {"Content-Type": "application/json"}, f"handoff-{idempotency_key}")

        first_scheduler = self.prepare_scheduler_authority(run_id, SchedulerPolicy(max_ticks=3, max_iterations=3), lease_ttl=5)
        first = first_scheduler.tick(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=HermeticTransport(handler=handler), policy=SchedulerPolicy(max_ticks=3, max_iterations=3), lease_ttl=5)
        self.assertEqual(first["tick_no"], 1)
        clock.advance(6)
        next_worker = Actor("mr2b0-worker-2", "mr2b0-worker-2-session", "worker", "runner", "mr2b0-tests")
        second_scheduler = self.prepare_scheduler_authority(run_id, SchedulerPolicy(max_ticks=3, max_iterations=3), worker=next_worker, lease_ttl=5)
        second = second_scheduler.tick(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=HermeticTransport(handler=handler), policy=SchedulerPolicy(max_ticks=3, max_iterations=3), lease_ttl=5)
        self.assertEqual(second["tick_no"], 2)
        self.assertNotEqual(first["session_id"], second["session_id"])
        with self.assertRaises(MaxControlError):
            first_scheduler.tick(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=HermeticTransport(handler=handler), policy=SchedulerPolicy(max_ticks=3, max_iterations=3), lease_ttl=5)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_execution_grant_consumptions WHERE grant_id=?", (grant["grant_id"],)).fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_scheduler_ticks WHERE run_id=?", (run_id,)).fetchone()[0], 2)
        self.assertTrue(second_scheduler.verify(run_id=run_id)["ok"])

    def test_twenty_scheduler_ticks_have_at_most_one_owner(self) -> None:
        run_id = self.prepare_running_run()
        grant = self.store.issue_live_execution_grant(run_id=run_id, profile_hash=self.profile.profile_hash, caps=self.grant_caps(2, max_iterations=2), reason="explicit hermetic scheduler race fixture", actor=self.admin)

        def handler(request: bytes, _headers, idempotency_key: str):
            wire = json.loads(request.decode("utf-8"))
            return TransportResponse(200, response_body(wire["model"], f"race-{idempotency_key}", project_id="mr2b0-project"), {"Content-Type": "application/json"}, f"race-{idempotency_key}")

        first_owner = Actor("race-worker-0", "race-session-0", "worker", "runner", "mr2b0-tests")
        self.prepare_scheduler_authority(run_id, SchedulerPolicy(max_ticks=2, max_iterations=2), worker=first_owner, lease_ttl=300)

        def tick(_index: int):
            worker = Actor(f"race-worker-{_index}", f"race-session-{_index}", "worker", "runner", "mr2b0-tests")
            scheduler = ForegroundScheduler(self.repo, worker, provider_store=self.store, admin_actor=self.admin)
            try:
                return scheduler.tick(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=HermeticTransport(handler=handler), policy=SchedulerPolicy(max_ticks=2, max_iterations=2))
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=20) as pool:
            values = list(pool.map(tick, range(20)))
        successes = [value for value in values if isinstance(value, dict)]
        self.assertEqual(len(successes), 1)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertLessEqual(db.execute("SELECT COUNT(*) FROM max_scheduler_ticks WHERE run_id=?", (run_id,)).fetchone()[0], 1)

    def test_register_bind_grant_and_twenty_consumers_leave_one_row(self) -> None:
        self.store.register_profile(profile=self.profile, actor=self.admin)
        run_id = self.prepare_running_run()
        grant = self.store.issue_live_execution_grant(run_id=run_id, profile_hash=self.profile.profile_hash, caps=self.grant_caps(10), reason="explicit hermetic test grant", actor=self.admin)

        def consume(index: int):
            worker = Actor(f"worker-{index}", f"session-{index}", "worker", "runner", "mr2b0-tests")
            try:
                return self.store.consume_execution_grant(grant_id=grant["grant_id"], run_id=run_id, project_id="mr2b0-project", profile_hash=self.profile.profile_hash, model_identity=self.profile.model_identity, network_policy_hash=self.profile.network_policy_hash, pricing_hash=self.profile.pricing.pricing_hash, budget_hash=self.store.get_run_binding(run_id=run_id)["budget_hash"], consumer=worker)
            except Exception as exc:
                return str(exc)

        with ThreadPoolExecutor(max_workers=20) as pool:
            values = list(pool.map(consume, range(20)))
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_execution_grant_consumptions").fetchone()[0], 1)
        self.assertEqual(sum(isinstance(value, dict) for value in values), 1)

    def test_codec_rejects_duplicate_json_and_requires_profile_binding(self) -> None:
        request = ModelRequestEnvelope(
            project_id="p", run_id="r", iteration_id="i",
            role_packet=RolePacket("p", "r", "b" * 64, "", "socratic", (), self.profile.model_identity, "c" * 64),
            model_identity=self.profile.model_identity,
            inference_profile=InferenceProfile(max_output_tokens=128),
            context={"provider_profile_hash": self.profile.profile_hash},
            request_payload={"phase": "exploration", "logical_call_id": "logical-1"},
        )
        encoded = OpenAICompatibleCodec.encode(request, self.profile)
        self.assertTrue(encoded.request_hash)
        bad = TransportResponse(200, '{"model":"hermetic-model/v1","model":"other","choices":[],"usage":{}}')
        with self.assertRaises(Exception):
            OpenAICompatibleCodec.decode(bad, request, self.profile)

    def test_usage_is_server_priced_and_adapter_is_hermetic(self) -> None:
        request = ModelRequestEnvelope(
            project_id="p", run_id="r", iteration_id="i",
            role_packet=RolePacket("p", "r", "b" * 64, "", "socratic", (), self.profile.model_identity, "c" * 64),
            model_identity=self.profile.model_identity,
            inference_profile=InferenceProfile(max_output_tokens=128),
            context={"provider_profile_hash": self.profile.profile_hash},
            request_payload={"phase": "exploration", "logical_call_id": "logical-1"},
        )
        transport = HermeticTransport([TransportResponse(200, response_body(), {"Content-Type": "application/json"}, "call-1")])
        adapter = OpenAICompatibleAdapter(self.profile, transport, usage_authority=ProviderUsageAuthority())
        response = adapter.dispatch(request, idempotency_key="idempotency-1")
        self.assertEqual(response.model_identity, self.profile.model_identity)
        self.assertEqual(transport.network_call_count, 0)
        self.assertEqual(transport.credential_read_count, 0)
        self.assertIn("cost_units", response.usage_receipt["amount"])

    def test_foreground_scheduler_uses_one_hermetic_run_next_and_durable_tick(self) -> None:
        run_id = self.prepare_running_run()
        grant = self.store.issue_live_execution_grant(run_id=run_id, profile_hash=self.profile.profile_hash, caps=self.grant_caps(2), reason="explicit hermetic scheduler fixture", actor=self.admin)

        def handler(request: bytes, _headers, idempotency_key: str):
            wire = json.loads(request.decode("utf-8"))
            return TransportResponse(200, response_body(wire["model"], f"call-{idempotency_key}", project_id="mr2b0-project"), {"Content-Type": "application/json"}, f"call-{idempotency_key}")

        transport = HermeticTransport(handler=handler)
        scheduler = self.prepare_scheduler_authority(run_id, SchedulerPolicy(max_ticks=2, max_iterations=2, max_no_progress=5))
        result = scheduler.tick(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=transport, policy=SchedulerPolicy(max_ticks=2, max_iterations=2, max_no_progress=5))
        self.assertEqual(result["tick_no"], 1)
        self.assertEqual(scheduler.status(run_id=run_id)["tick_count"], 1)
        self.assertTrue(scheduler.verify(run_id=run_id)["ok"], self.repo.list_events(run_id=run_id, cursor=0, limit=200))
        self.assertEqual(transport.network_call_count, 0)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_scheduler_ticks WHERE run_id=?", (run_id,)).fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_provider_usage_attestations WHERE run_id=?", (run_id,)).fetchone()[0], 1, {"result": result, "events": self.repo.list_events(run_id=run_id, cursor=0, limit=200)})

    def test_mr2b0r2_physical_attempt_slot_and_settled_replay_are_idempotent(self) -> None:
        run_id = self.prepare_running_run()
        grant = self.store.issue_live_execution_grant(
            run_id=run_id,
            profile_hash=self.profile.profile_hash,
            caps=self.grant_caps(1, max_iterations=1, max_provider_calls=1),
            reason="explicit physical attempt replay fixture",
            actor=self.admin,
        )

        def handler(request: bytes, _headers, idempotency_key: str):
            wire = json.loads(request.decode("utf-8"))
            return TransportResponse(200, response_body(wire["model"], f"physical-{idempotency_key}", project_id="mr2b0-project"), {"Content-Type": "application/json"}, f"physical-{idempotency_key}")

        transport = HermeticTransport(handler=handler)
        scheduler = self.prepare_scheduler_authority(run_id, SchedulerPolicy(max_ticks=1, max_iterations=1))
        scheduler.tick(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=transport, policy=SchedulerPolicy(max_ticks=1, max_iterations=1))
        self.assertEqual(len(transport.requests), 1)
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            claim = db.execute("SELECT c.*, u.state FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.run_id=? ORDER BY c.created_at DESC LIMIT 1", (run_id,)).fetchone()
            lease = db.execute("SELECT fencing_token FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
            attempt_count = db.execute("SELECT COUNT(*) FROM max_provider_dispatch_attempts WHERE grant_id=?", (grant["grant_id"],)).fetchone()[0]
        self.assertIsNotNone(claim)
        self.assertEqual(claim["state"], "settled")
        self.assertEqual(attempt_count, 1)
        replay = self.store.claim_provider_call(
            grant_id=grant["grant_id"],
            run_id=run_id,
            project_id="mr2b0-project",
            profile_hash=self.profile.profile_hash,
            model_identity=self.profile.model_identity,
            pricing_hash=self.profile.pricing.pricing_hash,
            logical_call_id=claim["logical_call_id"],
            idempotency_key=claim["idempotency_key"],
            actor=self.worker,
            fencing_token=int(lease["fencing_token"]),
        )
        self.assertTrue(replay["replay"])
        self.assertEqual(replay["intent_id"], claim["intent_id"])
        self.assertEqual(self.store.grant_usage(grant_id=grant["grant_id"])["usage"]["dispatch_count"], 1)
        self.assertTrue(self.store.verify(run_id=run_id)["ok"], self.store.verify(run_id=run_id))

    def test_mr2b0r2_unknown_recovery_consumes_exactly_one_second_physical_slot(self) -> None:
        non_idempotent = ProviderProfile.from_mapping(
            {
                **profile_mapping(),
                "profile_id": "hermetic-non-idempotent-profile",
                "capabilities": {
                    "structured_json": True,
                    "idempotency": False,
                    "result_query": False,
                    "usage_reporting": True,
                },
            }
        )
        registered = self.store.register_profile(profile=non_idempotent, actor=self.admin)
        self.profile = self.store.get_profile(profile_hash=registered["profile_hash"])
        run_id = self.prepare_running_run()
        grant = self.store.issue_live_execution_grant(
            run_id=run_id,
            profile_hash=self.profile.profile_hash,
            caps=self.grant_caps(2, max_iterations=2, max_provider_calls=2),
            reason="explicit unknown recovery physical slot fixture",
            actor=self.admin,
        )
        responses = [
            TransportResponse(200, {}, {}, "unknown-call", dispatch_known=False),
            TransportResponse(200, response_body(self.profile.model_identity, "recovered-call", project_id="mr2b0-project"), {"Content-Type": "application/json"}, "recovered-call"),
        ]
        transport = HermeticTransport(responses)
        policy = SchedulerPolicy(max_ticks=2, max_iterations=2, max_no_progress=5)
        first_scheduler = self.prepare_scheduler_authority(run_id, policy)
        first = first_scheduler.tick(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=transport, policy=policy)
        self.assertEqual(first["status"], "paused")
        self.assertEqual(len(transport.requests), 1)
        persistence = RunnerPersistence(self.repo)
        unfinished = persistence.latest_unfinished(run_id=run_id)
        self.assertIsNotNone(unfinished)
        logical_call_id = str(unfinished["logical_call_id"])
        consumed = persistence.consume_admin_decision(run_id=run_id, logical_call_id=logical_call_id, decision="retry", admin_actor=self.admin)
        self.assertFalse(consumed["idempotent"])
        resumed = self.repo.resume(run_id=run_id, actor=self.admin, lease_ttl=300)
        next_worker = Actor("mr2b0-recovery-worker", "mr2b0-recovery-session", "worker", "runner", "mr2b0-tests")
        persistence.handoff_runner(
            run_id=run_id,
            profile=provider_runner_profile(self.profile),
            admin_actor=self.admin,
            runner_actor=next_worker,
            admin_fencing_token=int(resumed["lease"]["fencing_token"]),
            lease_ttl=300,
        )
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            lease = db.execute("SELECT fencing_token FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
        recovery_authority = self.repo.usage_authority or ProviderUsageAuthority()
        recovery_adapter = OpenAICompatibleAdapter(
            self.profile,
            transport,
            usage_authority=recovery_authority,
            provider_store=self.store,
            actor=next_worker,
            grant_id=grant["grant_id"],
            fencing_token=int(lease["fencing_token"]),
        )
        recovery_runner = BoundedRunner(
            self.repo,
            next_worker,
            provider_runner_profile(self.profile),
            recovery_adapter,
            gateway=HermeticResearchGateway(),
            usage_authority=recovery_authority,
            fixture=False,
            lease_ttl=300,
        )
        second = recovery_runner.run_next(run_id=run_id)
        self.assertEqual(
            second["status"],
            "completed",
            {"second": second, "provider": self.store.verify(run_id=run_id), "runner": persistence.verify_run(run_id=run_id)},
        )
        self.assertEqual(len(transport.requests), 2)
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            attempts = db.execute("SELECT u.state FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.grant_id=? ORDER BY a.physical_attempt_no", (grant["grant_id"],)).fetchall()
            usage = db.execute("SELECT dispatch_count FROM max_provider_grant_usage_current WHERE grant_id=?", (grant["grant_id"],)).fetchone()
        self.assertEqual([row["state"] for row in attempts], ["unknown", "settled"])
        self.assertEqual(int(usage["dispatch_count"]), 2)
        self.assertTrue(self.store.verify(run_id=run_id)["ok"], self.store.verify(run_id=run_id))
        durable = self.store.provider_call(run_id=run_id, idempotency_key=unfinished["idempotency_key"])
        self.assertIsNotNone(durable)
        self.assertEqual(durable["intent_id"], unfinished["intent_id"])

    def test_admin_cli_complete_transition_flow_is_redacted_and_one_shot(self) -> None:
        """Exercise the explicit admin path without starting a runner/model."""

        database = Path(self.temp.name) / "cli-flow.db"
        charter = {
            "question": "MR-2B0 CLI transition fixture",
            "scope": "bounded hermetic control",
            "invariants": ["human approval", "terminal cancel"],
            "non_goals": ["network", "model"],
            "deliverables": ["audit"],
            "model_identity": self.profile.model_identity,
            "budget": {"iteration_count": 4, "input_tokens": 1000, "output_tokens": 1000, "cost_units": 100},
            "source_policy": {"network_allowed": False, "roles": ["primary"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        env = {
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }

        def cli(*args: str) -> dict:
            completed = subprocess.run(
                [sys.executable, "-m", "research_kb.cli", *args],
                cwd=Path(__file__).parents[1],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            value = json.loads(completed.stdout)
            transcript = json.dumps(value, ensure_ascii=False)
            self.assertNotIn(str(database), transcript)
            self.assertNotIn("api_key", transcript)
            self.assertNotIn("source_text", transcript)
            self.assertNotIn("fencing_token", transcript)
            return value

        initialized = cli("max", "init", "--database", str(database))
        self.assertEqual(initialized["schema_version"], CONTROL_SCHEMA_VERSION)
        proposed = cli(
            "max", "propose", "--database", str(database), "--project", "mr2b0-cli-project",
            "--charter-json", json.dumps(charter, separators=(",", ":")),
        )
        self.assertEqual(proposed["status"], "AWAITING_START_APPROVAL")
        approved = cli(
            "max", "approve", "--database", str(database), "--run-id", proposed["run_id"],
            "--charter-hash", proposed["charter_hash"], "--reason", "explicit CLI fixture approval",
        )
        self.assertEqual(approved["run"]["status"], "APPROVED")
        started = cli("max", "start", "--database", str(database), "--run-id", proposed["run_id"])
        self.assertEqual(started["run"]["status"], "RUNNING")
        with closing(sqlite3.connect(database)) as connection:
            fencing_token = connection.execute("SELECT fencing_token FROM max_leases WHERE run_id=?", (proposed["run_id"],)).fetchone()[0]
        paused = cli(
            "max", "pause", "--database", str(database), "--run-id", proposed["run_id"],
            "--fencing-token", str(fencing_token),
        )
        self.assertEqual(paused["run"]["status"], "PAUSED")
        resumed = cli("max", "resume", "--database", str(database), "--run-id", proposed["run_id"])
        self.assertEqual(resumed["run"]["status"], "RUNNING")
        with closing(sqlite3.connect(database)) as connection:
            fencing_token = connection.execute("SELECT fencing_token FROM max_leases WHERE run_id=?", (proposed["run_id"],)).fetchone()[0]
        cancelled = cli(
            "max", "cancel", "--database", str(database), "--run-id", proposed["run_id"],
            "--fencing-token", str(fencing_token),
        )
        self.assertEqual(cancelled["run"]["status"], "CANCELLED")
        status = cli("max", "status", "--database", str(database), "--run-id", proposed["run_id"])
        self.assertEqual(status["run"]["status"], "CANCELLED")
        first_page = cli("max", "events", "--database", str(database), "--run-id", proposed["run_id"], "--cursor", "0", "--limit", "3")
        self.assertEqual([item["sequence_no"] for item in first_page["events"]], [1, 2, 3])
        verified = cli("max", "verify", "--database", str(database), "--run-id", proposed["run_id"])
        self.assertTrue(verified["ok"])
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?", (proposed["run_id"],)).fetchone()[0], 1)

    def test_hermetic_scheduler_completes_48_tick_cycle_with_four_rehydrations(self) -> None:
        """Exercise the finite scheduler through every frozen cognitive boundary."""

        run_id = self.prepare_running_run(iteration_count=100)
        grant = self.store.issue_live_execution_grant(
            run_id=run_id,
            profile_hash=self.profile.profile_hash,
            caps=self.grant_caps(48, max_iterations=48, max_provider_calls=240),
            reason="explicit hermetic 48-tick acceptance fixture",
            actor=self.admin,
        )
        evidence_ids: list[str] = []

        def proposal_for(typed: dict, logical_call_id: str) -> dict:
            phase = str(typed.get("phase") or typed.get("round_type") or "exploration")
            call_spec_id = str(typed.get("call_spec_id") or "")
            target_id = str(typed.get("target_id") or "")
            hypothesis_id = f"mr1:hypothesis:{canonical_sha256(logical_call_id)[:48]}"
            proposal = {"objects": [], "relations": [], "artifact_links": [], "record_refs": [], "strategy": None, "output_summary": "bounded hermetic result", "role_outputs": [], "deliberation": None}
            if call_spec_id in {"lead_position", "rival_position"}:
                role = "lead" if call_spec_id == "lead_position" else "rival"
                proposal["deliberation"] = {"kind": "position", "role": role, "position": f"hermetic {role} position", "canonical_claim_ids": [], "canonical_evidence_ids": list(evidence_ids), "rationale": f"hermetic rationale {role}"}
            elif call_spec_id == "rival_cross_examination":
                proposal["deliberation"] = {"kind": "cross_examination", "examiner_role": "rival", "respondent_role": "lead", "question": "Which canonical evidence would falsify the lead position?", "challenged_claim_ids": []}
            elif call_spec_id == "lead_cross_examination_response":
                proposal["deliberation"] = {"kind": "correction", "role": "lead", "correction": "The bounded lead position remains qualified by canonical evidence.", "corrected_claim_ids": []}
            elif call_spec_id == "adjudicator":
                proposal["deliberation"] = {"kind": "adjudication", "validity_audit": {"auditor_role": "adjudicator", "passed": True, "facts_evidence_true": True, "normative_valid": True, "expression_clear": True, "role_fidelity": True, "findings": ["hermetic audit"], "audited_claim_ids": [], "rationale": "hermetic audit"}, "adjudication": {"value": "underdetermined", "rationale": "bounded hermetic adjudication", "rival_ids": [target_id], "canonical_evidence_ids": list(evidence_ids)}, "minority_reports": []}
            elif phase == "acquisition_review":
                evidence_id = f"mr1:evidence:{canonical_sha256(logical_call_id)[:48]}"
                evidence_ids.append(evidence_id)
                proposal["objects"] = [{"stable_id": evidence_id, "kind": "evidence", "project_id": "mr2b0-project", "version": 1, "payload": {"label": "hermetic evidence", "status": "candidate", "target_id": target_id}}]
                proposal["strategy"] = {"family": "direct", "query": "hermetic acquisition review", "target_ids": [target_id], "filters": {"fixture": True}, "result_ids": [], "new_evidence_ids": [evidence_id], "coverage_keys": ["source_role"]}
                proposal["artifact_links"] = [{"artifact_type": "search_strategy", "artifact": {"family": "direct", "query": "hermetic acquisition review", "coverage_keys": ["source_role"]}}]
            elif phase == "attack":
                objection_id = f"mr1:objection:{canonical_sha256(logical_call_id)[:48]}"
                proposal["objects"] = [{"stable_id": objection_id, "kind": "objection", "project_id": "mr2b0-project", "version": 1, "payload": {"label": "hermetic attack", "status": "candidate", "target_id": target_id}}]
                proposal["strategy"] = {"family": "counterevidence", "query": "hermetic attack", "target_ids": [target_id], "filters": {"fixture": True}, "result_ids": [], "new_evidence_ids": [], "coverage_keys": ["theoretical_opponent"]}
                proposal["artifact_links"] = [{"artifact_type": "attack_record", "artifact": {"target_id": target_id, "target_version_id": target_id, "outcome": "needs_review", "rationale": "hermetic adversarial probe"}}]
            elif phase == "rehydration":
                proposal["objects"] = [{"stable_id": hypothesis_id, "kind": "hypothesis", "project_id": "mr2b0-project", "version": 1, "payload": {"label": "hermetic rehydration", "status": "candidate"}}]
                proposal["strategy"] = {"family": "rehydration", "query": "hermetic rehydration", "target_ids": [target_id], "filters": {"fixture": True}, "result_ids": [], "new_evidence_ids": [], "coverage_keys": ["canonical_rebuild"]}
                proposal["artifact_links"] = [{"artifact_type": "rehydration_review", "artifact": {"canonical_rebuild": True, "drift_flags": []}}]
            else:
                proposal["objects"] = [{"stable_id": hypothesis_id, "kind": "hypothesis", "project_id": "mr2b0-project", "version": 1, "payload": {"label": "hermetic exploration", "status": "candidate"}}]
                proposal["strategy"] = {"family": "direct", "query": "hermetic exploration", "target_ids": [target_id], "filters": {"fixture": True}, "result_ids": [], "new_evidence_ids": [], "coverage_keys": ["conceptual_definition"]}
                proposal["artifact_links"] = [{"artifact_type": "search_strategy", "artifact": {"family": "direct", "query": "hermetic exploration", "coverage_keys": ["conceptual_definition"]}}]
            return proposal

        def handler(request: bytes, _headers, _idempotency_key: str):
            wire = json.loads(request.decode("utf-8"))
            typed = json.loads(wire["messages"][1]["content"])["typed_input"]
            logical_call_id = wire["metadata"]["logical_call_id"]
            proposal = proposal_for(typed, logical_call_id)
            body = {"id": f"call-{logical_call_id[:16]}", "object": "chat.completion", "created": 1, "model": wire["model"], "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps(proposal, separators=(",", ":"))}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}}
            return TransportResponse(200, json.dumps(body, separators=(",", ":")), {"Content-Type": "application/json"}, f"call-{logical_call_id[:16]}")

        transport = HermeticTransport(handler=handler)
        scheduler = self.prepare_scheduler_authority(run_id, SchedulerPolicy(max_ticks=48, max_iterations=48, max_consecutive_failures=5, max_no_progress=100, max_wall_clock_seconds=100000), lease_ttl=300)
        result = scheduler.run_bounded(run_id=run_id, profile=self.profile, grant_id=grant["grant_id"], transport=transport, max_ticks=48, policy=SchedulerPolicy(max_ticks=48, max_iterations=48, max_consecutive_failures=5, max_no_progress=100, max_wall_clock_seconds=100000))
        self.assertEqual(result["ticks_executed"], 48)
        self.assertEqual(result["stop_reason"], "max_iterations")
        self.assertEqual(transport.network_call_count, 0)
        self.assertEqual(transport.credential_read_count, 0)
        status = scheduler.status(run_id=run_id)
        self.assertEqual(status["tick_count"], 48)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_iteration_outcomes WHERE run_id=? AND status='completed'", (run_id,)).fetchone()[0], 48)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_iterations i JOIN max_iteration_outcomes o ON o.iteration_id=i.iteration_id WHERE i.run_id=? AND i.round_type='rehydration' AND o.status='completed'", (run_id,)).fetchone()[0], 4)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_provider_usage_attestations WHERE run_id=?", (run_id,)).fetchone()[0], len(transport.requests))
        self.assertTrue(self.repo.verify_run(run_id=run_id)["ok"])
        self.assertTrue(scheduler.verify(run_id=run_id)["ok"])


if __name__ == "__main__":
    unittest.main()
