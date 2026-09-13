from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from research_kb.max_research.contract import AcquisitionRequest, canonical_sha256, model_to_dict
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.provider import (
    InjectedCredentialResolver,
    InjectedDNSResolver,
    InjectedHTTPSConnector,
    LiveAuthorizationBundleStore,
    LiveIterationApprovalStore,
    LiveProviderTransportFactory,
    LiveRunnerExecutor,
    OpenAICompatibleHTTPSLiveTransport,
    ProviderProfile,
    ProviderStore,
    ProviderUsageAuthority,
    TransportResponse,
    live_execution_confirmation_hash,
    network_policy_hash,
)
from research_kb.max_research.scheduler import (
    AcquisitionControl,
    HermeticResearchGateway,
    LongRunningWorker,
    WorkerControl,
    provider_runner_profile,
    validate_staging_run,
)
from research_kb.policy import Actor


def _network_policy() -> dict:
    return {"policy_version": "mr2b2-offline/v1"}


def _profile_mapping() -> dict:
    return {
        "profile_id": "mr2b2-live-profile",
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
        "credential_ref": {"kind": "environment", "name": "MR2B2_OFFLINE_FIXTURE"},
        "network_policy_hash": network_policy_hash(_network_policy()),
        "pricing": {"pricing_id": "mr2b2-price", "pricing_version": "1", "currency": "USD", "unit": "cost_units", "input_per_1k": "1", "output_per_1k": "2", "cache_per_1k": "0", "reasoning_per_1k": "0", "effective_at": "2026-01-01T00:00:00.000Z", "source_label": "offline-fixture"},
    }


def _response_body(model: str, call_id: str = "offline-live-call") -> bytes:
    proposal = {
        "objects": [],
        "relations": [],
        "artifact_links": [],
        "record_refs": [],
        "strategy": None,
        "output_summary": "bounded offline live-shape result",
        "role_outputs": [],
        "deliberation": None,
    }
    value = {
        "id": call_id,
        "object": "chat.completion",
        "created": 1,
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps(proposal, separators=(",", ":"))}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
    }
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class _InjectedLiveFactory(LiveProviderTransportFactory):
    fixture_only = True

    def __init__(self, connector: InjectedHTTPSConnector) -> None:
        self.connector = connector
        self.resolver = InjectedCredentialResolver({"MR2B2_OFFLINE_FIXTURE": "offline-injected-value"})
        self.dns = InjectedDNSResolver({"provider.invalid": ["93.184.216.34"]})

    def create_for_permit(self, *, profile: ProviderProfile, permit, provider_store: ProviderStore):
        return OpenAICompatibleHTTPSLiveTransport(
            endpoint_origin=profile.endpoint_origin,
            endpoint_path_policy=profile.endpoint_path_policy,
            credential_ref=profile.credential_ref,
            network_policy=_network_policy(),
            credential_resolver=self.resolver,
            permit=permit,
            permit_validator=provider_store.validate_live_dispatch_permit,
            dns_resolver=self.dns,
            connector=self.connector,
        )


class MaxStageTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr2b2-mr3-")
        self.root = Path(self.temp.name)
        self.database = self.root / "control.db"
        self.admin = Actor("mr23-admin", "mr23-admin-session", "user", "admin", "mr23-tests")
        self.worker = Actor("mr23-worker", "mr23-worker-session", "worker", "runner", "mr23-tests")
        self.repo = MaxControlRepository(self.database)
        self.repo.initialize(fixture=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def prepare_run(self, *, project_id: str = "mr23-project", model_identity: str = "offline-model-placeholder/v1") -> tuple[str, dict]:
        charter = {
            "question": "Can a bounded long-running research control plane remain auditable?",
            "scope": "MR-2B2 and MR-3 offline validation",
            "invariants": ["human authority", "canonical evidence"],
            "non_goals": ["real network", "automatic ingest"],
            "deliverables": ["audit"],
            "model_identity": model_identity,
            "budget": {"iteration_count": 20, "input_tokens": 20000, "output_tokens": 2000, "cost_units": 1000},
            "source_policy": {"network_allowed": False, "roles": ["primary", "counterevidence"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        proposed = self.repo.propose(project_id=project_id, charter=charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="offline stage fixture", actor=self.admin)
        started = self.repo.start(run_id=proposed["run_id"], actor=self.admin, lease_ttl=300)
        return proposed["run_id"], started


class MR2B2Tests(MaxStageTestCase):
    def prepare_authority(self) -> dict:
        store = ProviderStore(self.repo)
        registered = store.register_profile(profile=ProviderProfile.from_mapping(_profile_mapping()), actor=self.admin)
        profile = store.get_profile(profile_hash=registered["profile_hash"])
        run_id, started = self.prepare_run(model_identity=profile.model_identity)
        store.bind_run_profile(run_id=run_id, profile_hash=profile.profile_hash, actor=self.admin)
        max_cost = profile.pricing.cost_units_for_usage(profile.authority_maximum_usage())
        caps = {"max_ticks": 1, "max_iterations": 1, "max_wall_clock_seconds": 300, "max_consecutive_failures": 1, "max_no_progress": 2, "max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cost_units": max_cost}
        grant = store.issue_live_execution_grant(run_id=run_id, profile_hash=profile.profile_hash, caps=caps, reason="one offline live-shaped iteration", actor=self.admin)
        binding = store.get_run_binding(run_id=run_id)
        store.consume_execution_grant(grant_id=grant["grant_id"], run_id=run_id, project_id=binding["project_id"], profile_hash=profile.profile_hash, model_identity=profile.model_identity, network_policy_hash=profile.network_policy_hash, pricing_hash=profile.pricing.pricing_hash, budget_hash=binding["budget_hash"], consumer=self.admin)
        authorization = store.issue_live_network_authorization(run_id=run_id, grant_id=grant["grant_id"], caps={"max_provider_calls": 1, "max_input_tokens": 512, "max_output_tokens": 32, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": max_cost}, network_policy=_network_policy(), reason="one injected HTTPS attempt", actor=self.admin)
        runner_profile = provider_runner_profile(profile)
        runner = RunnerPersistence(self.repo)
        runner.register_profile(profile=runner_profile, actor=self.admin)
        handoff = runner.handoff_runner(run_id=run_id, profile=runner_profile, admin_actor=self.admin, runner_actor=self.worker, admin_fencing_token=int(started["lease"]["fencing_token"]), lease_ttl=300)
        bundle = LiveAuthorizationBundleStore(store).create(run_id=run_id, grant_id=grant["grant_id"], authorization_ids=[authorization["authorization_id"]], actor=self.admin)
        approval = LiveIterationApprovalStore(self.repo).issue(run_id=run_id, grant_id=grant["grant_id"], bundle_id=bundle["bundle_id"], provider_profile_hash=profile.profile_hash, runner_profile_hash=runner_profile.profile_hash, reason="approve one bounded injected iteration", actor=self.admin)
        return {"store": store, "profile": profile, "runner_profile": runner_profile, "run_id": run_id, "grant": grant, "authorization": authorization, "bundle": bundle, "approval": approval, "handoff": handoff}

    @unittest.skipUnless(CONTROL_SCHEMA_VERSION == 21, "historical schema-21 assertion is not run by the dev11 control plane")
    def test_schema12_is_independent_and_contains_mr2b2_mr3_authority(self) -> None:
        self.assertEqual(CONTROL_SCHEMA_VERSION, 21)
        verified = self.repo.verify_database()
        self.assertTrue(verified["ok"], verified)
        with closing(sqlite3.connect(self.database)) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("max_live_iteration_approvals", tables)
            self.assertIn("max_worker_heartbeats", tables)
            self.assertIn("max_acquisition_validation_receipts", tables)
            self.assertNotIn("research_documents", tables)

    def test_one_human_approval_drives_exactly_one_injected_live_iteration(self) -> None:
        authority = self.prepare_authority()
        connector = InjectedHTTPSConnector(TransportResponse(200, _response_body(authority["profile"].model_identity), {"content-type": "application/json"}, "offline-live-call", True))
        factory = _InjectedLiveFactory(connector)
        executor = LiveRunnerExecutor(self.repo, self.worker, provider_store=authority["store"], transport_factory=factory, usage_authority=ProviderUsageAuthority())
        confirmation = live_execution_confirmation_hash(run_id=authority["run_id"], grant_id=authority["grant"]["grant_id"], bundle_id=authority["bundle"]["bundle_id"], profile_hash=authority["profile"].profile_hash, runner_profile_hash=authority["runner_profile"].profile_hash)
        result = executor.run_next(run_id=authority["run_id"], grant_id=authority["grant"]["grant_id"], bundle_id=authority["bundle"]["bundle_id"], provider_profile=authority["profile"], runner_profile=authority["runner_profile"], gateway=HermeticResearchGateway(), execute_live=True, confirmation_hash=confirmation, live_iteration_approval_id=authority["approval"]["live_iteration_approval_id"], lease_ttl=300)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(connector.network_call_count, 1)
        self.assertEqual(factory.dns.lookup_count, 1)
        self.assertEqual(factory.resolver.read_count, 1)
        self.assertEqual(LiveAuthorizationBundleStore(authority["store"]).status(run_id=authority["run_id"], bundle_id=authority["bundle"]["bundle_id"])["bundles"][0]["state"], "exhausted")
        status = LiveIterationApprovalStore(self.repo).status(run_id=authority["run_id"])
        self.assertIsNotNone(status["approvals"][0]["consumption"])
        verified = self.repo.verify_run(run_id=authority["run_id"])
        self.assertTrue(verified["ok"], verified["issues"])
        with self.assertRaises(MaxControlError):
            executor.run_next(run_id=authority["run_id"], grant_id=authority["grant"]["grant_id"], bundle_id=authority["bundle"]["bundle_id"], provider_profile=authority["profile"], runner_profile=authority["runner_profile"], gateway=HermeticResearchGateway(), execute_live=True, confirmation_hash=confirmation, live_iteration_approval_id=authority["approval"]["live_iteration_approval_id"], lease_ttl=300)
        self.assertEqual(connector.network_call_count, 1)

    def test_missing_or_wrong_iteration_approval_fails_before_any_io(self) -> None:
        authority = self.prepare_authority()
        connector = InjectedHTTPSConnector(TransportResponse(200, _response_body(authority["profile"].model_identity), {}, "should-not-run", True))
        executor = LiveRunnerExecutor(self.repo, self.worker, provider_store=authority["store"], transport_factory=_InjectedLiveFactory(connector), usage_authority=ProviderUsageAuthority())
        confirmation = live_execution_confirmation_hash(run_id=authority["run_id"], grant_id=authority["grant"]["grant_id"], bundle_id=authority["bundle"]["bundle_id"], profile_hash=authority["profile"].profile_hash, runner_profile_hash=authority["runner_profile"].profile_hash)
        with self.assertRaises(MaxControlError):
            executor.run_next(run_id=authority["run_id"], grant_id=authority["grant"]["grant_id"], bundle_id=authority["bundle"]["bundle_id"], provider_profile=authority["profile"], runner_profile=authority["runner_profile"], gateway=HermeticResearchGateway(), execute_live=True, confirmation_hash=confirmation, live_iteration_approval_id="not-an-approval", lease_ttl=300)
        self.assertEqual(connector.network_call_count, 0)

    def test_concurrent_human_approval_is_one_idempotent_authority(self) -> None:
        authority = self.prepare_authority()
        store = LiveIterationApprovalStore(self.repo)

        def issue(_: int):
            return store.issue(run_id=authority["run_id"], grant_id=authority["grant"]["grant_id"], bundle_id=authority["bundle"]["bundle_id"], provider_profile_hash=authority["profile"].profile_hash, runner_profile_hash=authority["runner_profile"].profile_hash, reason="approve one bounded injected iteration", actor=self.admin)

        with ThreadPoolExecutor(max_workers=20) as pool:
            values = list(pool.map(issue, range(20)))
        self.assertEqual(len({item["live_iteration_approval_id"] for item in values}), 1)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_iteration_approvals").fetchone()[0], 1)

    def test_append_only_approval_and_bundle_records_reject_mutation(self) -> None:
        authority = self.prepare_authority()
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE max_live_iteration_approvals SET reason_hash=?", ("0" * 64,))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM max_live_authorization_bundles WHERE bundle_id=?", (authority["bundle"]["bundle_id"],))


class MR3Tests(MaxStageTestCase):
    def prepare_worker_run(self) -> tuple[str, object]:
        run_id, started = self.prepare_run(model_identity="worker-model/v1")
        profile = provider_runner_profile(ProviderProfile.from_mapping({**_profile_mapping(), "model_identity": "worker-model/v1"}))
        persistence = RunnerPersistence(self.repo)
        persistence.register_profile(profile=profile, actor=self.admin)
        persistence.handoff_runner(run_id=run_id, profile=profile, admin_actor=self.admin, runner_actor=self.worker, admin_fencing_token=int(started["lease"]["fencing_token"]), lease_ttl=300)
        return run_id, profile

    def test_restartable_foreground_worker_has_bounded_heartbeats_and_commands(self) -> None:
        run_id, profile = self.prepare_worker_run()
        control = WorkerControl(self.repo)
        calls: list[int] = []

        def step():
            calls.append(len(calls) + 1)
            return {"run_id": run_id, "status": "running", "iteration_number": len(calls)}

        first = LongRunningWorker(self.repo, self.worker, step=step, control=control, sleeper=lambda _: None).run(run_id=run_id, runner_profile=profile, max_ticks=2, max_wall_clock_seconds=60, lease_ttl=300)
        self.assertEqual(first["ticks_executed"], 2)
        command = control.issue_command(run_id=run_id, command="drain", reason="bounded maintenance", actor=self.admin)
        second = LongRunningWorker(self.repo, self.worker, step=step, control=control, sleeper=lambda _: None).run(run_id=run_id, runner_profile=profile, max_ticks=2, max_wall_clock_seconds=60, lease_ttl=300)
        self.assertEqual(second["stop_reason"], "admin_drain")
        self.assertEqual(len(calls), 2)
        self.assertEqual(control.status(run_id=run_id)["current"]["state"], "draining")
        self.assertEqual(control.pending_command(run_id=run_id), None)
        self.assertTrue(control.verify(run_id=run_id)["ok"])
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_worker_command_consumptions WHERE command_id=?", (command["command_id"],)).fetchone()[0], 1)

    def test_stale_worker_cannot_append_heartbeat_or_consume_command(self) -> None:
        run_id, profile = self.prepare_worker_run()
        persistence = RunnerPersistence(self.repo)
        lease = persistence.claim_runner_lease(run_id=run_id, profile=profile, actor=self.worker, lease_ttl=300)
        control = WorkerControl(self.repo)
        command = control.issue_command(run_id=run_id, command="stop", reason="stale-fence test", actor=self.admin)
        stale = Actor("stale-worker", "stale-session", "worker", "runner", "mr23-tests")
        with self.assertRaises(MaxControlError):
            control.heartbeat(run_id=run_id, actor=stale, fencing_token=int(lease["fencing_token"]), state="running", tick_count=0)
        with self.assertRaises(MaxControlError):
            control.consume_command(command_id=command["command_id"], actor=stale, fencing_token=int(lease["fencing_token"]))

    def test_worker_rejects_conflicting_pending_commands(self) -> None:
        run_id, _ = self.prepare_worker_run()
        control = WorkerControl(self.repo)
        first = control.issue_command(run_id=run_id, command="drain", reason="first administrative decision", actor=self.admin)
        replay = control.issue_command(run_id=run_id, command="drain", reason="first administrative decision", actor=self.admin)
        self.assertEqual(replay["command_id"], first["command_id"])
        self.assertTrue(replay["idempotent"])
        with self.assertRaises(MaxControlError):
            control.issue_command(run_id=run_id, command="stop", reason="contradictory administrative decision", actor=self.admin)
        self.assertEqual(control.status(run_id=run_id)["pending_command_count"], 1)
        self.assertTrue(control.verify(run_id=run_id)["ok"])

    def _acquisition_request(self, run_id: str) -> AcquisitionRequest:
        state = self.repo.get_state(run_id=run_id)
        target_id = sorted(state["latest_by_id"])[0]
        run = self.repo.get_run(run_id)
        return AcquisitionRequest(project_id="mr23-project", run_id=run_id, source_policy_hash=run["source_policy_hash"], research_gap="Need a falsifying primary source for the leading control claim", target_ids=(target_id,), why_needed="The current state has no direct counterexample", expected_information_gain="could reverse the current adjudication", possible_falsification=("A primary source shows the mechanism is absent",), desired_source_role="counterevidence", preferred_types=("article",), preferred_languages=("en", "zh"), max_candidates=2)

    def _staging(self, *, tamper_hash: bool = False) -> Path:
        staging = self.root / ("staging-bad" if tamper_hash else "staging-good")
        (staging / "files").mkdir(parents=True, exist_ok=True)
        payload = b"Offline source acquisition candidate."
        document = staging / "files" / "candidate.txt"
        document.write_bytes(payload)
        content_hash = hashlib.sha256(payload).hexdigest()
        manifest = {"schema_version": 1, "worker": "offline-fixture", "run_id": "worker-run-1", "params": {}, "inputs": [], "outputs": [{"path": "files/candidate.txt", "content_hash": "0" * 64 if tamper_hash else content_hash, "bytes": len(payload)}], "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z", "exit_code": 0, "summary": {}, "notes": []}
        (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        return staging

    def test_acquisition_is_human_approved_independently_validated_and_never_ingested(self) -> None:
        run_id, _ = self.prepare_worker_run()
        control = AcquisitionControl(self.repo)
        request = self._acquisition_request(run_id)
        proposed = control.propose(request=request, actor=self.worker)
        control.decide(request_id=request.request_id, decision="approve", reason="gap is material", actor=self.admin)
        grant = control.authorize_worker(request_id=request.request_id, worker_id=self.worker.actor_id, worker_session=self.worker.session_id, max_candidates=2, max_bytes=1024 * 1024, ttl_seconds=300, reason="one isolated staging run", actor=self.admin)
        claim = control.claim(request_id=request.request_id, worker_grant_id=grant["worker_grant_id"], actor=self.worker)
        with self.assertRaises(MaxControlError):
            control.stage(request_id=request.request_id, claim_id=claim["claim_id"], staging_manifest_hash="0" * 64, validation_hash="1" * 64, dry_run_manifest_hash="2" * 64, candidate_count=1, total_bytes=1, actor=self.worker)
        with self.assertRaises(MaxControlError):
            control.validate_and_stage(request_id=request.request_id, claim_id=claim["claim_id"], staging_run=self._staging(), actor=self.worker)
        staged = control.validate_and_stage(request_id=request.request_id, claim_id=claim["claim_id"], staging_run=self._staging(), actor=self.admin)
        accepted = control.decide(request_id=request.request_id, decision="accept", reason="independent validation passed", validation_hash=staged["validation_hash"], dry_run_manifest_hash=staged["dry_run_manifest_hash"], actor=self.admin)
        self.assertEqual(accepted["state"], "accepted")
        self.assertTrue(control.verify(run_id=run_id)["ok"])
        self.assertTrue(self.repo.verify_run(run_id=run_id)["ok"])
        with closing(sqlite3.connect(self.database)) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertNotIn("research_documents", tables)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_acquisition_stage_receipts").fetchone()[0], 1)
        self.assertEqual(proposed["state"], "proposed")

    def test_staging_validator_rejects_hash_tampering_and_flags_duplicates(self) -> None:
        with self.assertRaises(MaxControlError):
            validate_staging_run(self._staging(tamper_hash=True), max_candidates=2, max_total_bytes=1024 * 1024)
        good = self._staging()
        document_hash = hashlib.sha256((good / "files" / "candidate.txt").read_bytes()).hexdigest()
        result = validate_staging_run(good, max_candidates=2, max_total_bytes=1024 * 1024, existing_content_hashes={document_hash})
        self.assertEqual(result["dry_run_manifest"]["duplicate_count"], 1)
        self.assertEqual(result["dry_run_manifest"]["eligible_count"], 0)
        self.assertFalse(result["validation"]["checks"]["authoritative_ingest_performed"])

    def test_staging_validator_rejects_linked_root(self) -> None:
        good = self._staging()
        linked = self.root / "linked-staging"
        try:
            linked.symlink_to(good, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("this Windows account cannot create a directory symlink")
        with self.assertRaises(MaxControlError):
            validate_staging_run(linked, max_candidates=2, max_total_bytes=1024 * 1024)

    def test_acquisition_claim_is_single_winner_and_append_only(self) -> None:
        run_id, _ = self.prepare_worker_run()
        control = AcquisitionControl(self.repo)
        request = self._acquisition_request(run_id)
        control.propose(request=request, actor=self.worker)
        control.decide(request_id=request.request_id, decision="approve", reason="concurrency fixture", actor=self.admin)
        grant = control.authorize_worker(request_id=request.request_id, worker_id=self.worker.actor_id, worker_session=self.worker.session_id, max_candidates=1, max_bytes=1024, ttl_seconds=300, reason="single claimant", actor=self.admin)

        def claim(_: int):
            try:
                return control.claim(request_id=request.request_id, worker_grant_id=grant["worker_grant_id"], actor=self.worker)
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=20) as pool:
            values = list(pool.map(claim, range(20)))
        successes = [item for item in values if isinstance(item, dict)]
        self.assertEqual(len({item["claim_id"] for item in successes}), 1)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_acquisition_claims").fetchone()[0], 1)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM max_acquisition_claims")

    def test_combined_database_verification_includes_worker_and_acquisition(self) -> None:
        run_id, profile = self.prepare_worker_run()
        worker = LongRunningWorker(
            self.repo,
            self.worker,
            step=lambda: {"run_id": run_id, "status": "running", "iteration_number": 1},
            control=WorkerControl(self.repo),
            sleeper=lambda _: None,
        )
        worker.run(
            run_id=run_id,
            runner_profile=profile,
            max_ticks=1,
            max_wall_clock_seconds=60,
            lease_ttl=300,
        )
        request = self._acquisition_request(run_id)
        AcquisitionControl(self.repo).propose(request=request, actor=self.worker)
        result = self.repo.verify_database()
        self.assertTrue(result["ok"], result["issues"])
        self.assertIn("worker", result)
        self.assertIn("acquisition", result)
        self.assertTrue(result["runs"][run_id]["worker"]["ok"])
        self.assertTrue(result["runs"][run_id]["acquisition"]["ok"])

        backup = self.root / "mr3-backup.db"
        restored = self.root / "mr3-restored.db"
        self.assertTrue(self.repo.backup(backup)["verification"]["ok"])
        restored_repo = MaxControlRepository(restored)
        self.assertTrue(restored_repo.restore(backup)["verification"]["ok"])
        restored_status = WorkerControl(restored_repo).status(run_id=run_id)
        restored_acquisition = AcquisitionControl(restored_repo).status(run_id=run_id)
        self.assertEqual(restored_status["heartbeat_count"], 3)
        self.assertEqual(restored_acquisition["requests"][0]["request_id"], request.request_id)


if __name__ == "__main__":
    unittest.main()
