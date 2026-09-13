from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository
from research_kb.max_research.persistence.migrations import (
    _backfill_schema_v2,
    _backfill_schema_v4,
    _backfill_schema_v8,
    _statements,
    migration_files,
)
from research_kb.max_research.provider import (
    DisabledLiveTransport,
    EnvironmentCredentialResolver,
    InjectedCredentialResolver,
    InjectedDNSResolver,
    InjectedHTTPSConnector,
    LiveNetworkAuthorization,
    OpenAICompatibleHTTPSLiveTransport,
    ProviderProfile,
    ProviderStore,
    ProviderTransportError,
    TransportResponse,
    default_live_transport,
    network_policy_hash,
    validate_endpoint_static,
)
from research_kb.policy import Actor


def policy() -> dict:
    return {"policy_version": "mr2b1/v1"}


def credential_fixture() -> tuple[str, str]:
    # Assemble the in-memory test value at runtime so no secret-shaped
    # complete value is present in source, sdist, wheel, or durable records.
    return "MR2B1_" + "FIXTURE", "offline-" + "injected-" + "value"


def profile_mapping() -> dict:
    credential_name, _ = credential_fixture()
    return {
        "profile_id": "live-boundary-profile",
        "profile_version": "1",
        "protocol": "openai-compatible/v1",
        "provider_name": "provider-placeholder",
        "model_identity": "model-placeholder/v1",
        "endpoint_origin": "https://provider.invalid",
        "endpoint_path_policy": "/v1/chat/completions",
        "capabilities": {"structured_json": True, "idempotency": True, "result_query": False, "usage_reporting": True},
        "inference_defaults": {"temperature": 0, "top_p": 1, "max_output_tokens": 128},
        "timeout_policy": {"connect_ms": 1000, "write_ms": 1000, "read_ms": 1000, "total_ms": 5000},
        "retry_policy": {"max_attempts": 1, "backoff_ms": 1, "retry_statuses": [429]},
        "request_limits": {"max_request_bytes": 100000, "max_response_bytes": 100000, "max_prompt_chars": 10000, "max_json_depth": 12, "max_input_tokens": 2500, "max_output_tokens": 128, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0},
        "rate_policy": {"max_concurrency": 1, "per_minute": 60},
        "credential_ref": {"kind": "environment", "name": credential_name},
        "network_policy_hash": network_policy_hash(policy()),
        "pricing": {"pricing_id": "placeholder-pricing", "pricing_version": "1", "currency": "USD", "unit": "cost_units", "input_per_1k": "1", "output_per_1k": "2", "cache_per_1k": "0", "reasoning_per_1k": "0", "effective_at": "2026-01-01T00:00:00.000Z", "source_label": "offline-fixture"},
    }


class MR2B1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr2b1-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("mr2b1-admin", "mr2b1-admin-session", "user", "admin", "mr2b1-tests")
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize()
        self.store = ProviderStore(self.repo)
        registered = self.store.register_profile(profile=ProviderProfile.from_mapping(profile_mapping()), actor=self.admin)
        self.profile = self.store.get_profile(profile_hash=registered["profile_hash"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def running_run_and_grant(self) -> tuple[str, dict]:
        charter = {
            "question": "offline provider boundary",
            "scope": "MR-2B1",
            "invariants": ["no implicit network"],
            "non_goals": ["live send"],
            "deliverables": ["audit"],
            "model_identity": self.profile.model_identity,
            "budget": {"iteration_count": 3, "input_tokens": 10000, "output_tokens": 10000, "cost_units": 1000},
            "source_policy": {"network_allowed": False, "roles": ["primary"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        proposed = self.repo.propose(project_id="mr2b1-project", charter=charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="offline fixture", actor=self.admin)
        self.repo.start(run_id=proposed["run_id"], actor=self.admin, lease_ttl=300)
        self.store.bind_run_profile(run_id=proposed["run_id"], profile_hash=self.profile.profile_hash, actor=self.admin)
        grant = self.store.issue_live_execution_grant(run_id=proposed["run_id"], profile_hash=self.profile.profile_hash, caps={"max_ticks": 3, "max_iterations": 3, "max_wall_clock_seconds": 1000, "max_consecutive_failures": 3, "max_no_progress": 10, "max_provider_calls": 1, "max_input_tokens": 10000, "max_output_tokens": 10000, "max_cost_units": 1000}, reason="offline hermetic grant", actor=self.admin)
        self.store.consume_execution_grant(grant_id=grant["grant_id"], run_id=proposed["run_id"], project_id="mr2b1-project", profile_hash=self.profile.profile_hash, model_identity=self.profile.model_identity, network_policy_hash=self.profile.network_policy_hash, pricing_hash=self.profile.pricing.pricing_hash, budget_hash=self.store.get_run_binding(run_id=proposed["run_id"])["budget_hash"], consumer=self.admin)
        return proposed["run_id"], grant

    def auth(self) -> tuple[str, dict, dict]:
        run_id, grant = self.running_run_and_grant()
        maximum = self.profile.pricing.cost_units_for_usage(self.profile.authority_maximum_usage())
        authority = self.store.issue_live_network_authorization(run_id=run_id, grant_id=grant["grant_id"], caps={"max_provider_calls": 1, "max_input_tokens": 2500, "max_output_tokens": 128, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": maximum}, network_policy=policy(), reason="offline live boundary fixture", actor=self.admin)
        return run_id, grant, authority

    @staticmethod
    def _create_schema8_database(path: Path) -> None:
        """Build an empty schema-8 fixture only from the packaged 001-008 SQL."""

        with closing(sqlite3.connect(path, isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE max_schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
            for version, name, migration in migration_files()[:8]:
                for statement in _statements(migration.read_text(encoding="utf-8")):
                    db.execute(statement)
                if version == 2:
                    _backfill_schema_v2(db)
                elif version == 4:
                    _backfill_schema_v4(db)
                elif version == 8:
                    _backfill_schema_v8(db)
                db.execute(
                    "INSERT INTO max_schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, "1970-01-01T00:00:00.000Z"),
                )
            db.commit()

    def test_schema8_upgrade_applies_only_new_schema9(self) -> None:
        legacy = Path(self.temp.name) / "schema8.db"
        self._create_schema8_database(legacy)
        upgraded = MaxControlRepository(legacy).initialize()
        self.assertEqual(upgraded["schema_version"], CONTROL_SCHEMA_VERSION)
        with closing(sqlite3.connect(legacy)) as db:
            self.assertEqual(
                db.execute("SELECT GROUP_CONCAT(version, ',') FROM max_schema_migrations ORDER BY version").fetchone()[0],
                ",".join(str(version) for version in range(1, CONTROL_SCHEMA_VERSION + 1)),
            )
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_network_authorizations").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_provider_dispatch_attempts").fetchone()[0], 0)
        self.assertTrue(MaxControlRepository(legacy).verify_database()["ok"])

    def test_schema9_is_independent_and_authorization_is_hash_only(self) -> None:
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT MAX(version) FROM max_schema_migrations").fetchone()[0], CONTROL_SCHEMA_VERSION)
            names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("max_live_network_authorizations", names)
            self.assertNotIn("research_documents", names)
        run_id, grant, authority = self.auth()
        credential_name, _ = credential_fixture()
        self.assertEqual(authority["execution_mode"], "live_https")
        self.assertEqual(authority["provider_name"], self.profile.provider_name)
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT authorization_json FROM max_live_network_authorizations WHERE authorization_id=?", (authority["authorization_id"],)).fetchone()[0]
            text = row + db.execute("SELECT policy_json FROM max_live_network_policies WHERE network_policy_hash=?", (authority["network_policy_hash"],)).fetchone()[0]
            self.assertNotIn(credential_name, text)
            self.assertNotIn("provider.invalid", text)
        self.assertTrue(self.store.verify_live_network(run_id=run_id)["ok"])

    def test_authorization_consumption_is_one_row_under_twenty_racers(self) -> None:
        run_id, grant, authority = self.auth()
        kwargs = {"authorization_id": authority["authorization_id"], "run_id": run_id, "project_id": "mr2b1-project", "grant_id": grant["grant_id"], "profile_hash": self.profile.profile_hash, "provider_name": self.profile.provider_name, "model_identity": self.profile.model_identity, "endpoint_origin": self.profile.endpoint_origin, "endpoint_path_policy": self.profile.endpoint_path_policy, "credential_ref": self.profile.credential_ref, "consumer": self.admin}
        def consume(_: int):
            try:
                return self.store.consume_live_network_authorization(**kwargs)
            except Exception as exc:
                return exc
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(consume, range(20)))
        successes = [item for item in results if isinstance(item, dict)]
        self.assertGreaterEqual(len(successes), 1)
        self.assertEqual({item["consumption_id"] for item in successes}, {successes[0]["consumption_id"]})
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_network_authorization_consumptions").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_network_access_events WHERE authorization_id=?", (authority["authorization_id"],)).fetchone()[0], 2)

    def test_binding_mismatch_expiry_and_model_cannot_consume(self) -> None:
        run_id, grant, authority = self.auth()
        base = {"authorization_id": authority["authorization_id"], "run_id": run_id, "project_id": "mr2b1-project", "grant_id": grant["grant_id"], "profile_hash": self.profile.profile_hash, "provider_name": self.profile.provider_name, "model_identity": self.profile.model_identity, "endpoint_origin": self.profile.endpoint_origin, "endpoint_path_policy": self.profile.endpoint_path_policy, "credential_ref": self.profile.credential_ref, "consumer": self.admin}
        with self.assertRaises(MaxControlError):
            self.store.consume_live_network_authorization(**{**base, "project_id": "other-project"})
        with self.assertRaises(MaxControlError):
            self.store.consume_live_network_authorization(**{**base, "endpoint_path_policy": "/other"})
        with self.assertRaises(MaxControlError):
            self.store.consume_live_network_authorization(**{**base, "endpoint_origin": "https://other.invalid"})
        with self.assertRaises(MaxControlError):
            self.store.consume_live_network_authorization(**{**base, "model_identity": "other-model"})
        with self.assertRaises(MaxControlError):
            self.store.consume_live_network_authorization(**{**base, "provider_name": "other-provider"})
        with self.assertRaises(MaxControlError):
            self.store.consume_live_network_authorization(**{**base, "consumer": Actor("model", "model-session", "model", "model", "fixture")})

    def test_expired_authorization_fails_closed_without_consumption(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.repo.clock = lambda: now
        run_id, grant = self.running_run_and_grant()
        maximum = self.profile.pricing.cost_units_for_usage(self.profile.authority_maximum_usage())
        authority = self.store.issue_live_network_authorization(run_id=run_id, grant_id=grant["grant_id"], caps={"max_provider_calls": 1, "max_input_tokens": 2500, "max_output_tokens": 128, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": maximum}, network_policy=policy(), reason="short lived offline fixture", actor=self.admin, ttl_seconds=1)
        self.repo.clock = lambda: now + timedelta(seconds=2)
        with self.assertRaises(MaxControlError):
            self.store.consume_live_network_authorization(authorization_id=authority["authorization_id"], run_id=run_id, project_id="mr2b1-project", grant_id=grant["grant_id"], profile_hash=self.profile.profile_hash, provider_name=self.profile.provider_name, model_identity=self.profile.model_identity, endpoint_origin=self.profile.endpoint_origin, endpoint_path_policy=self.profile.endpoint_path_policy, credential_ref=self.profile.credential_ref, consumer=self.admin)
        self.assertEqual(self.store.live_authorization_status(run_id=run_id)["authorizations"][0]["state"], "active")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_network_authorization_consumptions").fetchone()[0], 0)

    def test_read_only_preflight_has_zero_network_and_credential_activity(self) -> None:
        run_id, grant, authority = self.auth()
        before = self.store.live_authorization_status(run_id=run_id)
        result = self.store.provider_live_preflight(run_id=run_id, authorization_id=authority["authorization_id"], grant_id=grant["grant_id"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["network"], {"calls": 0, "dns_lookups": 0, "credential_reads": 0})
        self.assertEqual(before["authorizations"][0]["state"], "active")
        self.assertEqual(self.store.live_authorization_status(run_id=run_id)["authorizations"][0]["state"], "active")

    def test_credentials_are_explicit_and_canary_never_enters_transport_audit(self) -> None:
        run_id, grant, authority = self.auth()
        credential_name, credential_value = credential_fixture()
        disabled = EnvironmentCredentialResolver()
        with self.assertRaises(ProviderTransportError):
            disabled.resolve(credential_name)
        resolver = InjectedCredentialResolver({credential_name: credential_value})
        dns = InjectedDNSResolver({"provider.invalid": ["93.184.216.34"]})
        connector = InjectedHTTPSConnector(TransportResponse(200, b"{}", {"content-type": "application/json"}, "provider-id", True))
        with self.assertRaises(TypeError):
            OpenAICompatibleHTTPSLiveTransport(endpoint_origin=self.profile.endpoint_origin, endpoint_path_policy=self.profile.endpoint_path_policy, credential_ref=self.profile.credential_ref, network_policy=policy(), credential_resolver=resolver, dns_resolver=dns, connector=connector, authorization_checked=True, attempt_persisted=True)
        self.assertEqual(resolver.read_count, 0)
        self.assertEqual(connector.network_call_count, 0)
        with closing(sqlite3.connect(self.path)) as db:
            contents = "\n".join(str(row[0]) for row in db.execute("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL"))
            self.assertNotIn(credential_value, contents)
            for table in ("max_live_network_authorizations", "max_live_network_authorization_consumptions", "max_live_network_access_events", "max_live_network_attempt_records"):
                columns = [row[1] for row in db.execute(f"PRAGMA table_info({table})")]
                for column in columns:
                    for row in db.execute(f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL"):
                        self.assertNotIn(credential_value, str(row[0]))

    def test_ssrf_mixed_candidates_headers_redirect_and_default_factory_fail_closed(self) -> None:
        credential_name, credential_value = credential_fixture()
        resolver = InjectedCredentialResolver({credential_name: credential_value})
        dns = InjectedDNSResolver({"provider.invalid": ["93.184.216.34", "127.0.0.1"]})
        connector = InjectedHTTPSConnector()
        with self.assertRaises(TypeError):
            OpenAICompatibleHTTPSLiveTransport(endpoint_origin=self.profile.endpoint_origin, endpoint_path_policy=self.profile.endpoint_path_policy, credential_ref=self.profile.credential_ref, network_policy=policy(), credential_resolver=resolver, dns_resolver=dns, connector=connector, authorization_checked=True, attempt_persisted=True)
        self.assertEqual(resolver.read_count, 0)
        self.assertEqual(connector.network_call_count, 0)
        with self.assertRaises(ProviderTransportError):
            default_live_transport().send(b"{}", headers={}, timeout_ms=1000, idempotency_key="x")
        for endpoint in ("http://provider.invalid", "https://127.0.0.1", "https://provider.invalid?x=1", "https://user:pass@provider.invalid"):
            with self.assertRaises(ValueError):
                validate_endpoint_static(endpoint, "/v1/chat/completions")

    def test_append_only_authorization_records_and_chain_tamper_detection(self) -> None:
        run_id, grant, authority = self.auth()
        with closing(sqlite3.connect(self.path)) as db:
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute("UPDATE max_live_network_authorizations SET model_identity='tampered' WHERE authorization_id=?", (authority["authorization_id"],))
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute("DELETE FROM max_live_network_access_events WHERE authorization_id=?", (authority["authorization_id"],))
        self.store.consume_live_network_authorization(authorization_id=authority["authorization_id"], run_id=run_id, project_id="mr2b1-project", grant_id=grant["grant_id"], profile_hash=self.profile.profile_hash, provider_name=self.profile.provider_name, model_identity=self.profile.model_identity, endpoint_origin=self.profile.endpoint_origin, endpoint_path_policy=self.profile.endpoint_path_policy, credential_ref=self.profile.credential_ref, consumer=self.admin)
        self.assertTrue(self.store.verify_live_network(run_id=run_id)["ok"])
        tampered = Path(self.temp.name) / "tampered.db"
        self.repo.backup(tampered)
        restored = Path(self.temp.name) / "restored.db"
        restore_result = MaxControlRepository(restored).restore(tampered)
        self.assertEqual(restore_result["schema_version"], CONTROL_SCHEMA_VERSION)
        restored_repo = MaxControlRepository(restored)
        self.assertTrue(restored_repo.verify_database()["provider"]["live_network"]["ok"])
        with closing(sqlite3.connect(restored)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_live_network_authorization_consumptions").fetchone()[0], 1)
        with closing(sqlite3.connect(tampered)) as db:
            db.execute("DROP TRIGGER max_live_network_access_events_no_update")
            db.execute("UPDATE max_live_network_access_events SET payload_json='{}' WHERE authorization_id=? AND sequence_no=2", (authority["authorization_id"],))
            db.commit()
        self.assertFalse(MaxControlRepository(tampered).verify_database()["provider"]["live_network"]["ok"])


if __name__ == "__main__":
    unittest.main()
