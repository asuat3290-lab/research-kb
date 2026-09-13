"""Offline v14R3 durable DNS attempt/receipt closure tests."""

from __future__ import annotations

import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from _mr4b1b_schema22_fixture import Schema22NativeFixture
from research_kb.max_research.dns_attempt import DNSAttemptError, DNSAttemptStore
from research_kb.max_research.persistence import MaxControlRepository
from research_kb.max_research.persistence.version import CONTROL_SCHEMA_VERSION
from research_kb.max_research.provider.live import InjectedDNSResolver


class DurableDNSAttemptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Schema22NativeFixture(legacy_dns_receipt=False, release_residual_runner_claim=True)
        self.store = DNSAttemptStore(self.fixture.repo)
        self.phrase = "APPROVE MR-4B1 DNS PREFLIGHT " + self.fixture.dns_request["request_hash"]

    def tearDown(self) -> None:
        self.fixture.close()

    def _execute(self, resolver: InjectedDNSResolver, **kwargs):
        phrase = kwargs.pop("confirmation_phrase", self.phrase)
        return self.store.execute(
            preview_id=self.fixture.preview["preview_id"],
            request_id=self.fixture.dns_request["request_id"],
            confirmation_phrase=phrase,
            actor=self.fixture.admin,
            resolver=resolver,
            allow_execute=True,
            **kwargs,
        )

    def _read_all_control_text(self) -> str:
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            rows = connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL "
                "UNION ALL SELECT 'attempt', attempt_json FROM max_live_canary_dns_attempts "
                "UNION ALL SELECT 'event', payload_json FROM max_live_canary_dns_attempt_events "
                "UNION ALL SELECT 'current', current_json FROM max_live_canary_dns_attempt_current "
                "UNION ALL SELECT 'receipt', receipt_json FROM max_live_canary_dns_attempt_receipts"
            ).fetchall()
        return "\n".join(str(item) for row in rows for item in row)

    def test_01_schema25_and_zero_external_baseline(self) -> None:
        verified = self.fixture.repo.verify_database()
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertTrue(verified["quick_check"])
        self.assertTrue(verified["foreign_keys"])
        self.assertEqual(verified["provider"]["counts"]["calls"], 0)

    def test_02_explicit_execute_flag_is_required(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)})
        with self.assertRaises(DNSAttemptError) as caught:
            self.store.execute(
                preview_id=self.fixture.preview["preview_id"],
                request_id=self.fixture.dns_request["request_id"],
                confirmation_phrase=self.phrase,
                actor=self.fixture.admin,
                resolver=resolver,
            )
        self.assertEqual(caught.exception.error_code, "EXECUTE_FLAG_REQUIRED")
        self.assertEqual(resolver.lookup_count, 0)

    def test_03_wrong_phrase_fails_before_attempt(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)})
        with self.assertRaises(DNSAttemptError) as caught:
            self._execute(resolver, confirmation_phrase="APPROVE MR-4B1 DNS PREFLIGHT " + "0" * 64)
        self.assertEqual(caught.exception.error_code, "CONFIRMATION_INVALID")
        self.assertEqual(resolver.lookup_count, 0)
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_consumptions").fetchone()[0], 0)

    def test_04_success_commits_two_phase_chain_once(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")})
        result = self._execute(resolver)
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "DNS_PREFLIGHT_PASSED")
        self.assertEqual(resolver.lookup_count, 1)
        self.assertEqual(result["resolver_calls"], 1)
        self.assertEqual(result["retries"], 0)
        self.assertEqual(result["candidate_count"], 3)
        self.assertFalse(result["raw_ip_persisted"])
        status = self.store.status(attempt_id=result["attempt_id"])
        self.assertEqual(status["counts"]["authority_consumptions"], 1)
        self.assertEqual(status["counts"]["request_consumptions"], 1)
        self.assertEqual(status["receipt"]["status"], "passed")
        verified = self.store.verify(attempt_id=result["attempt_id"])
        self.assertTrue(verified["ok"], verified)
        self.assertEqual(verified["event_count"], 4)

    def test_05_replay_is_rejected_without_second_resolver_call(self) -> None:
        first_resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)})
        first = self._execute(first_resolver)
        replay_resolver = InjectedDNSResolver({"opencode.ai": ("1.1.1.1",)})
        with self.assertRaises(DNSAttemptError) as caught:
            self._execute(replay_resolver)
        self.assertEqual(caught.exception.error_code, "ALREADY_CONSUMED")
        self.assertEqual(first_resolver.lookup_count, 1)
        self.assertEqual(replay_resolver.lookup_count, 0)
        self.assertEqual(self.store.status(attempt_id=first["attempt_id"])["counts"]["retries"], 0)

    def test_06_unsafe_address_is_bounded_failure(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("127.0.0.1",)})
        result = self._execute(resolver)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "FAILED_WITH_BOUNDED_RESULT")
        self.assertEqual(result["error_code"], "SSRF_ADDRESS_BLOCKED")
        self.assertFalse(result["all_global"])
        self.assertFalse(result["ssrf_safe"])
        self.assertEqual(result["resolver_calls"], 1)

    def test_07_candidate_cap_is_not_truncated(self) -> None:
        addresses = tuple(f"8.8.8.{number}" for number in range(1, 18))
        result = self._execute(InjectedDNSResolver({"opencode.ai": addresses}))
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "FAILED_WITH_BOUNDED_RESULT")
        self.assertEqual(result["candidate_count"], 17)
        self.assertFalse(result["cap_satisfied"])
        self.assertEqual(result["error_code"], "DNS_CANDIDATE_LIMIT_EXCEEDED")

    def test_08_empty_and_invalid_results_are_bounded(self) -> None:
        empty = self._execute(InjectedDNSResolver({"opencode.ai": ()}))
        self.assertEqual(empty["error_code"], "DNS_RESULT_EMPTY")
        self.tearDown()
        self.setUp()
        invalid = self._execute(InjectedDNSResolver({"opencode.ai": ("not-an-ip",)}))
        self.assertEqual(invalid["error_code"], "DNS_ADDRESS_INVALID")

    def test_09_resolver_exception_becomes_unknown_without_receipt(self) -> None:
        class RaisingResolver:
            lookup_count = 0

            def resolve(self, host, port):
                self.lookup_count += 1
                raise RuntimeError("resolver failure with no address material")

        resolver = RaisingResolver()
        result = self._execute(resolver)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "UNKNOWN_AFTER_RESOLVER_START")
        self.assertEqual(resolver.lookup_count, 1)
        status = self.store.status(attempt_id=result["attempt_id"])
        self.assertIsNone(status["receipt"])
        self.assertEqual(status["counts"]["authority_consumptions"], 1)
        self.assertEqual(status["counts"]["request_consumptions"], 1)

    def test_10_transaction_a_crash_rolls_back_before_resolver(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)})
        with self.assertRaises(DNSAttemptError):
            self._execute(resolver, fault_stage="attempt_claim")
        self.assertEqual(resolver.lookup_count, 0)
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_consumptions").fetchone()[0], 0)

    def test_11_recovery_after_resolver_started_never_retries(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)})
        started = self._execute(resolver, fault_stage="after_resolver_started")
        self.assertEqual(resolver.lookup_count, 0)
        self.assertEqual(started["resolver_started"], True)
        recovered = self.store.recover_unknown(attempt_id=started["attempt_id"], actor=self.fixture.admin)
        self.assertEqual(recovered["state"], "UNKNOWN_AFTER_RESOLVER_START")
        self.assertEqual(self.store.status(attempt_id=started["attempt_id"])["counts"]["retries"], 0)
        with self.assertRaises(DNSAttemptError):
            self._execute(InjectedDNSResolver({"opencode.ai": ("1.1.1.1",)}))

    def test_12_normalization_failure_recovers_unknown(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)})
        with self.assertRaises(DNSAttemptError) as caught:
            self._execute(resolver, fault_stage="result_normalization")
        self.assertEqual(caught.exception.error_code, "CONTROL_PLANE_FAILURE")
        self.assertEqual(resolver.lookup_count, 1)
        status = self.store.status(request_id=self.fixture.dns_request["request_id"])
        self.assertEqual(status["state"], "UNKNOWN_AFTER_RESOLVER_START")
        self.assertIsNone(status["receipt"])

    def test_13_receipt_transaction_failure_recovers_unknown(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)})
        result = self._execute(resolver, fault_stage="receipt_transaction")
        self.assertEqual(resolver.lookup_count, 1)
        self.assertEqual(result["state"], "UNKNOWN_AFTER_RESOLVER_START")
        self.assertIsNone(self.store.status(attempt_id=result["attempt_id"])["receipt"])

    def test_14_unknown_recovery_is_idempotent(self) -> None:
        started = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}), fault_stage="after_resolver_started")
        first = self.store.recover_unknown(attempt_id=started["attempt_id"], actor=self.fixture.admin)
        second = self.store.recover_unknown(attempt_id=started["attempt_id"], actor=self.fixture.admin)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])

    def test_15_concurrency_twenty_has_one_winner(self) -> None:
        def run_one(_):
            resolver = InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)})
            try:
                value = self._execute(resolver)
                return "winner", resolver.lookup_count, value
            except DNSAttemptError as exc:
                return exc.error_code, resolver.lookup_count, None

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(run_one, range(20)))
        self.assertEqual(sum(1 for item in results if item[0] == "winner"), 1)
        self.assertEqual(sum(item[1] for item in results), 1)
        self.assertEqual(self.store.status(request_id=self.fixture.dns_request["request_id"])["counts"]["authority_consumptions"], 1)

    def test_16_raw_ip_never_enters_control_plane_text(self) -> None:
        secret_address = "8.8.8.77"
        result = self._execute(InjectedDNSResolver({"opencode.ai": (secret_address,)}))
        self.assertTrue(result["ok"])
        self.assertNotIn(secret_address, self._read_all_control_text())

    def test_17_phrase_and_addresses_are_not_persisted(self) -> None:
        result = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.78",)}))
        text = self._read_all_control_text()
        self.assertNotIn(self.phrase, text)
        self.assertNotIn("8.8.8.78", text)
        self.assertNotIn("APPROVE MR-4B1 DNS PREFLIGHT", text)
        self.assertFalse(result.get("raw_ip_persisted", True))

    def test_18_event_chain_has_typed_failure_stages(self) -> None:
        result = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            rows = connection.execute("SELECT state,failure_stage FROM max_live_canary_dns_attempt_events WHERE attempt_id=? ORDER BY sequence_no", (result["attempt_id"],)).fetchall()
        self.assertEqual([row[0] for row in rows], ["resolver_started", "resolver_returned", "receipt_committed", "DNS_PREFLIGHT_PASSED"])
        self.assertEqual(rows[0][1], "resolver_started")
        self.assertEqual(rows[-1][1], "receipt_committed")

    def test_19_legacy_receipt_table_remains_empty(self) -> None:
        self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_dns_receipts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_receipts").fetchone()[0], 1)

    def test_20_status_is_redacted_and_counts_are_separate(self) -> None:
        result = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        status = self.store.status(attempt_id=result["attempt_id"])
        rendered = json.dumps(status, sort_keys=True)
        self.assertNotIn("8.8.8.8", rendered)
        self.assertNotIn(self.phrase, rendered)
        self.assertEqual(status["counts"], {"attempts": 1, "retries": 0, "authority_consumptions": 1, "request_consumptions": 1})

    def test_21_verify_rejects_tampered_current_projection(self) -> None:
        result = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            connection.execute("UPDATE max_live_canary_dns_attempt_current SET current_hash=? WHERE attempt_id=?", ("0" * 64, result["attempt_id"]))
            connection.commit()
        verified = self.store.verify(attempt_id=result["attempt_id"])
        self.assertFalse(verified["ok"])
        self.assertIn("current_projection", verified["issues"])

    def test_22_backup_restore_preserves_attempt_chain(self) -> None:
        result = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        root = Path(self.fixture.database).parent
        backup = root / "v14r3-backup.db"
        restored = root / "v14r3-restored.db"
        self.fixture.repo.backup(backup)
        restored_repo = MaxControlRepository(restored)
        restored_repo.restore(backup)
        restored_store = DNSAttemptStore(restored_repo)
        self.assertTrue(restored_store.verify(attempt_id=result["attempt_id"])["ok"])

    def test_23_no_recovery_for_unknown_old_object(self) -> None:
        with self.assertRaises(DNSAttemptError) as caught:
            self.store.recover_unknown(attempt_id="legacy-v14-unknown", actor=self.fixture.admin)
        self.assertEqual(caught.exception.error_code, "ATTEMPT_NOT_FOUND")
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempts").fetchone()[0], 0)

    def test_24_non_admin_cannot_consume_dns_authority(self) -> None:
        from research_kb.policy import Actor

        actor = Actor("researcher", "researcher-session", "agent", "researcher", "offline-test")
        with self.assertRaises(DNSAttemptError) as caught:
            self.store.execute(
                preview_id=self.fixture.preview["preview_id"], request_id=self.fixture.dns_request["request_id"],
                confirmation_phrase=self.phrase, actor=actor, allow_execute=True,
                resolver=InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}),
            )
        self.assertEqual(caught.exception.error_code, "FORBIDDEN")

    def test_25_repository_has_no_external_activity_after_success(self) -> None:
        self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        verified = self.fixture.repo.verify_database()
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["provider"]["counts"]["calls"], 0)
        self.assertEqual(verified["provider"]["counts"]["physical_attempts"], 0)

    def test_26_execute_result_contains_only_bounded_fields(self) -> None:
        result = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        forbidden = {"address", "addresses", "ip", "ips", "raw_ip", "credential", "prompt", "source_text"}
        self.assertTrue(forbidden.isdisjoint(result))

    def test_27_request_and_authority_consumption_are_exactly_once(self) -> None:
        result = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            rows = connection.execute("SELECT consumption_type,COUNT(*) FROM max_live_canary_dns_attempt_consumptions WHERE attempt_id=? GROUP BY consumption_type", (result["attempt_id"],)).fetchall()
        self.assertEqual(sorted((row[0], row[1]) for row in rows), [("authority", 1), ("request", 1)])

    def test_28_recovery_does_not_create_receipt_or_live_authority(self) -> None:
        started = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}), fault_stage="after_resolver_started")
        self.store.recover_unknown(attempt_id=started["attempt_id"], actor=self.fixture.admin)
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_receipts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_jit_authorities").fetchone()[0], 0)

    def test_29_malformed_resolver_does_not_leak_exception_value(self) -> None:
        class BadResolver:
            lookup_count = 0

            def resolve(self, host, port):
                self.lookup_count += 1
                return [object()]

        result = self._execute(BadResolver())
        self.assertEqual(result["error_code"], "DNS_ADDRESS_INVALID")
        self.assertNotIn("object at", json.dumps(result))

    def test_30_final_report_facts_are_stable_and_bounded(self) -> None:
        result = self._execute(InjectedDNSResolver({"opencode.ai": ("8.8.8.8",)}))
        verified = self.store.verify(attempt_id=result["attempt_id"])
        self.assertEqual(verified["external_actions"], {"resolver_calls": 1, "retries": 0, "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0, "provider_calls": 0, "cost_units": 0})
        self.assertEqual(result["state"], "DNS_PREFLIGHT_PASSED")


if __name__ == "__main__":
    unittest.main()
