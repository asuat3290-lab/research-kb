"""Offline MR-4B1C-NP0 tests for the durable Live Network Policy boundary."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from _mr4b1b_schema22_fixture import (
    Schema22NativeFixture,
    network_policy_mapping,
    provider_profile_mapping,
)
from research_kb.max_research.approval_preview import (
    LiveApprovalPreviewError,
    LiveApprovalPreviewStore,
)
from research_kb.max_research.contract import canonical_json, canonical_sha256
from research_kb.max_research.dns_attempt import DNSAttemptStore
from research_kb.max_research.lifetime_separation import PreparationSnapshotError
from research_kb.max_research.persistence import MaxControlError, MaxControlRepository
from research_kb.max_research.provider import (
    InjectedDNSResolver,
    ProviderProfile,
    ProviderStore,
)
from research_kb.policy import Actor


class LiveNetworkPolicyClosureTests(unittest.TestCase):
    """Exercise only disposable control databases; no governed DB is opened."""

    def setUp(self) -> None:
        self.fixture = Schema22NativeFixture(
            legacy_dns_receipt=False,
            release_residual_runner_claim=True,
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def _clone(self, name: str) -> Path:
        target = Path(self.fixture.temp.name) / name
        shutil.copy2(self.fixture.database, target)
        return target

    def _durable_dns(self) -> dict[str, object]:
        return DNSAttemptStore(self.fixture.repo).execute(
            preview_id=self.fixture.preview["preview_id"],
            request_id=self.fixture.dns_request["request_id"],
            confirmation_phrase="APPROVE MR-4B1 DNS PREFLIGHT " + self.fixture.dns_request["request_hash"],
            actor=self.fixture.admin,
            resolver=InjectedDNSResolver(
                {"opencode.ai": ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")}
            ),
            allow_execute=True,
        )

    @staticmethod
    def _remove_binding_and_policy(path: Path) -> None:
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.execute("DROP TRIGGER max_live_network_policy_bindings_no_update")
            connection.execute("DROP TRIGGER max_live_network_policy_bindings_no_delete")
            connection.execute("DELETE FROM max_live_network_policy_bindings")
            connection.execute("DROP TRIGGER max_live_network_policies_no_update")
            connection.execute("DROP TRIGGER max_live_network_policies_no_delete")
            connection.execute("DELETE FROM max_live_network_policies")
            connection.executescript(
                """
                CREATE TRIGGER max_live_network_policy_bindings_no_update
                BEFORE UPDATE ON max_live_network_policy_bindings BEGIN
                    SELECT RAISE(ABORT, 'Max live network policy bindings are append-only');
                END;
                CREATE TRIGGER max_live_network_policy_bindings_no_delete
                BEFORE DELETE ON max_live_network_policy_bindings BEGIN
                    SELECT RAISE(ABORT, 'Max live network policy bindings are append-only');
                END;
                CREATE TRIGGER max_live_network_policies_no_update
                BEFORE UPDATE ON max_live_network_policies BEGIN
                    SELECT RAISE(ABORT, 'Max live network policies are append-only');
                END;
                CREATE TRIGGER max_live_network_policies_no_delete
                BEFORE DELETE ON max_live_network_policies BEGIN
                    SELECT RAISE(ABORT, 'Max live network policies are append-only');
                END;
                """
            )

    @staticmethod
    def _tamper_policy_payload(path: Path) -> None:
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            row = connection.execute(
                "SELECT network_policy_hash, policy_json FROM max_live_network_policies LIMIT 1"
            ).fetchone()
            assert row is not None
            value = json.loads(row[1])
            value["max_dns_candidates"] = 8
            connection.execute(
                "DROP TRIGGER max_live_network_policies_no_update"
            )
            connection.execute(
                "UPDATE max_live_network_policies SET policy_json=? WHERE network_policy_hash=?",
                (canonical_json(value), row[0]),
            )

    def test_fresh_registration_and_snapshot_create_server_owned_policy_binding(self) -> None:
        mapping = provider_profile_mapping()
        mapping["profile_id"] = "server-owned-policy-profile"
        mapping["network_policy"] = network_policy_mapping()
        registered = self.fixture.provider_store.register_profile(
            profile=ProviderProfile.from_mapping(mapping), actor=self.fixture.admin
        )
        with closing(self.fixture.repo._connect(read_only=True)) as connection:
            policy_count = connection.execute(
                "SELECT COUNT(*) FROM max_live_network_policies WHERE network_policy_hash=?",
                (self.fixture.network_policy["network_policy_hash"],),
            ).fetchone()[0]
            profile_row = connection.execute(
                "SELECT profile_json FROM max_provider_profiles WHERE profile_hash=?",
                (registered["profile_hash"],),
            ).fetchone()
            binding_count = connection.execute(
                "SELECT COUNT(*) FROM max_live_network_policy_bindings WHERE run_id=?",
                (self.fixture.run_id,),
            ).fetchone()[0]
        self.assertEqual(policy_count, 1)
        self.assertIsNotNone(profile_row)
        self.assertIn("network_policy", json.loads(profile_row["profile_json"]))
        self.assertEqual(binding_count, 1)

    def test_policy_registration_replay_is_idempotent_and_unique(self) -> None:
        policy = dict(network_policy_mapping())
        policy["max_dns_candidates"] = 8
        first = self.fixture.provider_store.register_network_policy(
            policy=policy, actor=self.fixture.admin
        )
        second = self.fixture.provider_store.register_network_policy(
            policy=policy, actor=self.fixture.admin
        )
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["network_policy_hash"], second["network_policy_hash"])

    def test_missing_policy_fails_at_live_preview_without_writing(self) -> None:
        self._durable_dns()
        clone = self._clone("missing-policy.db")
        self._remove_binding_and_policy(clone)
        before = hashlib.sha256(clone.read_bytes()).hexdigest()
        repository = MaxControlRepository(clone, clock=self.fixture.clock)
        store = LiveApprovalPreviewStore(
            repository, expected_release_identity=self.fixture.release
        )
        with self.assertRaises(LiveApprovalPreviewError):
            store.create_approval_preview(
                preparation_preview_id=self.fixture.preview["preview_id"],
                actor=self.fixture.admin,
            )
        after = hashlib.sha256(clone.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.assertIn(
            "prepared Run lacks a valid live network policy binding",
            ProviderStore(repository).verify_live_network(run_id=self.fixture.run_id)["issues"],
        )

    def test_policy_hash_mismatch_is_rejected_by_lookup_and_verifier(self) -> None:
        clone = self._clone("tampered-policy.db")
        self._tamper_policy_payload(clone)
        repository = MaxControlRepository(clone, clock=self.fixture.clock)
        with closing(repository._connect(read_only=True, verify_schema=False)) as connection:
            with self.assertRaises(MaxControlError):
                ProviderStore.registered_network_policy(
                    connection,
                    network_policy_hash_value=self.fixture.network_policy["network_policy_hash"],
                )
        verified = ProviderStore(repository).verify_live_network(run_id=self.fixture.run_id)
        self.assertFalse(verified["ok"])
        self.assertTrue(any("policy hash mismatch" in issue for issue in verified["issues"]))

    def test_cross_project_and_release_drift_fail_closed(self) -> None:
        with closing(self.fixture.repo._connect(read_only=True, verify_schema=False)) as connection:
            run = connection.execute(
                "SELECT * FROM max_runs WHERE run_id=?", (self.fixture.run_id,)
            ).fetchone()
            provider = connection.execute(
                "SELECT * FROM max_run_provider_bindings WHERE run_id=?",
                (self.fixture.run_id,),
            ).fetchone()
            profile = connection.execute(
                "SELECT * FROM max_provider_profiles WHERE profile_hash=?",
                (self.fixture.profile.profile_hash,),
            ).fetchone()
            self.assertIsNotNone(run)
            self.assertIsNotNone(provider)
            self.assertIsNotNone(profile)
            foreign_run = dict(run)
            foreign_run["project_id"] = "different-project"
            with self.assertRaises(MaxControlError):
                ProviderStore.materialize_network_policy_binding(
                    connection,
                    run=foreign_run,
                    provider=provider,
                    profile=profile,
                    release_identity_hash=canonical_sha256(self.fixture.release),
                    actor=self.fixture.admin,
                    now="2026-08-16T14:00:10.000Z",
                )
            with self.assertRaises(MaxControlError):
                ProviderStore.validate_network_policy_binding(
                    connection,
                    run_id=self.fixture.run_id,
                    expected_release_identity_hash="0" * 64,
                )

    def test_model_and_endpoint_profile_drift_fail_closed(self) -> None:
        clone = self._clone("model-drift.db")
        with closing(sqlite3.connect(clone, isolation_level=None)) as connection:
            connection.execute("DROP TRIGGER max_run_provider_bindings_no_update")
            connection.execute(
                "UPDATE max_run_provider_bindings SET model_identity=? WHERE run_id=?",
                ("drifted-model", self.fixture.run_id),
            )
        repository = MaxControlRepository(clone, clock=self.fixture.clock)
        with closing(repository._connect(read_only=True, verify_schema=False)) as connection:
            with self.assertRaises(MaxControlError):
                ProviderStore.validate_network_policy_binding(
                    connection, run_id=self.fixture.run_id
                )

        endpoint_clone = self._clone("endpoint-drift.db")
        with closing(sqlite3.connect(endpoint_clone, isolation_level=None)) as connection:
            row = connection.execute(
                "SELECT profile_hash, profile_json FROM max_provider_profiles WHERE profile_hash=?",
                (self.fixture.profile.profile_hash,),
            ).fetchone()
            self.assertIsNotNone(row)
            value = json.loads(row[1])
            value["endpoint_origin"] = "https://drift.invalid"
            connection.execute("DROP TRIGGER max_provider_profiles_no_update")
            connection.execute(
                "UPDATE max_provider_profiles SET profile_json=? WHERE profile_hash=?",
                (canonical_json(value), row[0]),
            )
        endpoint_repository = MaxControlRepository(endpoint_clone, clock=self.fixture.clock)
        with closing(endpoint_repository._connect(read_only=True, verify_schema=False)) as connection:
            with self.assertRaises(MaxControlError):
                ProviderStore.validate_network_policy_binding(
                    connection, run_id=self.fixture.run_id
                )

    def test_client_cannot_forge_policy_mapping_for_profile_hash(self) -> None:
        mapping = provider_profile_mapping()
        mapping["profile_id"] = "forged-policy-profile"
        forged_policy = dict(network_policy_mapping())
        forged_policy["max_dns_candidates"] = 8
        mapping["network_policy"] = forged_policy
        with self.assertRaises(MaxControlError):
            self.fixture.provider_store.register_profile(
                profile=ProviderProfile.from_mapping(mapping), actor=self.fixture.admin
            )
        with closing(self.fixture.repo._connect(read_only=True)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_provider_profiles WHERE profile_id=?",
                    ("forged-policy-profile",),
                ).fetchone()[0],
                0,
            )

    def test_policy_update_and_delete_are_rejected(self) -> None:
        policy_hash = self.fixture.network_policy["network_policy_hash"]
        with self.assertRaises(sqlite3.IntegrityError):
            with closing(sqlite3.connect(self.fixture.database)) as connection:
                connection.execute(
                    "UPDATE max_live_network_policies SET policy_hash=? WHERE network_policy_hash=?",
                    ("0" * 64, policy_hash),
                )
        with self.assertRaises(sqlite3.IntegrityError):
            with closing(sqlite3.connect(self.fixture.database)) as connection:
                connection.execute(
                    "DELETE FROM max_live_network_policies WHERE network_policy_hash=?",
                    (policy_hash,),
                )
        self.assertEqual(
            self.fixture.provider_store.network_policy_status(
                network_policy_hash_value=policy_hash
            )["network_policy_hash"],
            policy_hash,
        )

    def test_twenty_concurrent_registrations_create_one_authoritative_policy(self) -> None:
        policy = dict(network_policy_mapping())
        policy["max_dns_candidates"] = 8

        def register_once(_: int) -> dict[str, object]:
            return self.fixture.provider_store.register_network_policy(
                policy=policy, actor=self.fixture.admin
            )

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(register_once, range(20)))
        hashes = {str(item["network_policy_hash"]) for item in results}
        self.assertEqual(len(hashes), 1)
        with closing(self.fixture.repo._connect(read_only=True)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_network_policies WHERE network_policy_hash=?",
                    (next(iter(hashes)),),
                ).fetchone()[0],
                1,
            )

    def test_binding_replay_and_backup_restore_preserve_lookup(self) -> None:
        with closing(self.fixture.repo._connect(read_only=False, verify_schema=False)) as connection:
            run = connection.execute(
                "SELECT * FROM max_runs WHERE run_id=?", (self.fixture.run_id,)
            ).fetchone()
            provider = connection.execute(
                "SELECT * FROM max_run_provider_bindings WHERE run_id=?",
                (self.fixture.run_id,),
            ).fetchone()
            profile = connection.execute(
                "SELECT * FROM max_provider_profiles WHERE profile_hash=?",
                (self.fixture.profile.profile_hash,),
            ).fetchone()
            replay = ProviderStore.materialize_network_policy_binding(
                connection,
                run=run,
                provider=provider,
                profile=profile,
                release_identity_hash=canonical_sha256(self.fixture.release),
                actor=self.fixture.admin,
                now="2026-08-16T14:00:10.000Z",
            )
        self.assertTrue(replay["idempotent"])
        backup = Path(self.fixture.temp.name) / "policy-backup.db"
        result = self.fixture.repo.backup(backup)
        self.assertTrue(result["verification"]["ok"], result)
        restored = MaxControlRepository(backup, clock=self.fixture.clock)
        with closing(restored._connect(read_only=True)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_network_policy_bindings WHERE run_id=?",
                    (self.fixture.run_id,),
                ).fetchone()[0],
                1,
            )
            self.assertTrue(
                ProviderStore.validate_network_policy_binding(
                    connection, run_id=self.fixture.run_id
                )["binding_hash"]
            )

    def test_server_owned_binding_reaches_native_preview_policy_gate(self) -> None:
        self._durable_dns()
        preview = LiveApprovalPreviewStore(
            self.fixture.repo, expected_release_identity=self.fixture.release
        ).create_approval_preview(
            preparation_preview_id=self.fixture.preview["preview_id"],
            actor=self.fixture.admin,
        )
        self.assertTrue(preview["ok"])
        self.assertEqual(preview["provider_calls"], 0)
        self.assertEqual(
            ProviderStore(self.fixture.repo).verify_live_network(
                run_id=self.fixture.run_id
            )["counts"]["policy_bindings"],
            1,
        )

    def test_snapshot_creation_missing_policy_is_fail_closed(self) -> None:
        clone = self._clone("missing-policy-snapshot.db")
        self._remove_binding_and_policy(clone)
        repository = MaxControlRepository(clone, clock=self.fixture.clock)
        from research_kb.max_research.lifetime_separation import PreparationSnapshotStore

        snapshots = PreparationSnapshotStore(
            repository, source_database=self.fixture.source_database
        )
        with self.assertRaises(PreparationSnapshotError):
            snapshots.create_snapshot(
                run_id=self.fixture.run_id,
                source_binding=self.fixture.source,
                preparation={
                    "request_hash": self.fixture.preparation["request_hash"],
                    "wire_request_hash": self.fixture.preparation["wire_request_hash"],
                    "request_manifest_hash": self.fixture.preparation["request_manifest_hash"],
                    "source_manifest_sha256": "4" * 64,
                },
                caps=self.fixture.native_caps(),
                release_identity=self.fixture.release,
                actor=self.fixture.admin,
            )


if __name__ == "__main__":
    unittest.main()
