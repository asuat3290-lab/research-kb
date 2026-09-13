"""Current schema-22 preparation-handoff and runner-verifier invariants.

This is the current successor for the former V13R1 fixture suite.  It uses
only the disposable schema-22 fixture and a temporary local source database;
official V11/V12/V13/Pilot databases are not opened.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from _mr4b1b_schema22_fixture import Schema22NativeFixture
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.preparation_handoff import (
    PREPARATION_CLAIM_HELD,
    PREPARED,
    PreparationHandoffError,
    PreparationHandoffStore,
)


class CurrentPreparationHandoffBehaviorTests(unittest.TestCase):
    """Schema-22 handoff, release, verifier, fencing, and restore coverage."""

    def setUp(self) -> None:
        self.fixture = Schema22NativeFixture()
        self.database = self.fixture.database
        self.repo = self.fixture.repo
        self.admin = self.fixture.admin
        self.worker = self.fixture.worker
        self.run_id = self.fixture.run_id
        self.snapshot = self.fixture.snapshot
        self.preview = self.fixture.preview
        self.dns_request = self.fixture.dns_request
        self.handoff = self.fixture.handoff
        self.preparation = self.fixture.preparation
        self.handoffs = self.fixture.handoffs

    def tearDown(self) -> None:
        self.fixture.close()

    def _rw(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def _handoff_args(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "snapshot_id": self.snapshot["snapshot_id"],
            "preview_id": self.preview["preview_id"],
            "dns_authority_id": self.dns_request["authority_id"],
            "dns_request_id": self.dns_request["request_id"],
            "preparation_claim_id": self.preparation["claim_id"],
            "fencing_token": self.preparation["fencing_token"],
            "worker": self.worker,
            "reservation_id": self.preparation["reservation_id"],
        }

    def _handoff_issues(self) -> list[str]:
        with closing(self.repo._connect(read_only=True, verify_schema=False)) as connection:
            return PreparationHandoffStore.verify_group_handoff(
                connection,
                run_id=self.run_id,
                group_id=self.handoff["call_group_id"],
                now=self.fixture.clock(),
            )

    def _runner_issues(self) -> list[str]:
        return list(RunnerPersistence(self.repo).verify_run(run_id=self.run_id)["issues"])

    def test_01_schema22_quick_foreign_keys_and_manifest(self) -> None:
        result = self.repo.verify_database()
        self.assertTrue(result["quick_check"])
        self.assertTrue(result["foreign_keys"])
        self.assertEqual(result["schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertTrue(result["schema_manifest"]["ok"])

    def test_02_handoff_is_server_owned_and_prepared(self) -> None:
        self.assertEqual(self.handoff["state"], PREPARED)
        with closing(self._rw()) as connection:
            row = connection.execute(
                "SELECT * FROM max_runner_preparation_handoffs WHERE handoff_id=?",
                (self.handoff["handoff_id"],),
            ).fetchone()
            current = connection.execute(
                "SELECT state FROM max_runner_preparation_handoff_current WHERE handoff_id=?",
                (self.handoff["handoff_id"],),
            ).fetchone()
            group = connection.execute(
                "SELECT lifecycle_state FROM max_runner_call_group_current WHERE group_id=?",
                (self.handoff["call_group_id"],),
            ).fetchone()
        self.assertEqual(row["actor_kind"], "worker")
        self.assertEqual(current["state"], PREPARED)
        self.assertEqual(group["lifecycle_state"], PREPARED)

    def test_03_claim_and_lease_have_authoritative_release_records(self) -> None:
        with closing(self._rw()) as connection:
            released = connection.execute(
                "SELECT claim_json,status,fencing_token FROM max_runner_invocation_claims WHERE claim_id=?",
                (self.handoff["released_claim_id"],),
            ).fetchone()
            lease = connection.execute(
                "SELECT released_at FROM max_leases WHERE run_id=?", (self.run_id,)
            ).fetchone()
        self.assertEqual(json.loads(released["claim_json"])["released_claim_id"], self.preparation["claim_id"])
        self.assertEqual(released["status"], "released")
        self.assertEqual(int(released["fencing_token"]), self.preparation["fencing_token"])
        self.assertIsNotNone(lease["released_at"])

    def test_04_handoff_transaction_rolls_back_on_mid_commit_failure(self) -> None:
        repo = type(self.repo)(self.fixture.pre_handoff_database, clock=self.fixture.clock)
        store = PreparationHandoffStore(repo, source_database=self.fixture.source_database)

        def fail_release(*_: object, **__: object) -> None:
            raise RuntimeError("simulated handoff failure")

        store._release_claim_and_lease = fail_release  # type: ignore[method-assign]
        with self.assertRaises(RuntimeError):
            store.handoff_preparation(**self._handoff_args())
        with closing(repo._connect(read_only=True, verify_schema=False)) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM max_runner_preparation_handoffs").fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT lifecycle_state FROM max_runner_call_group_current WHERE group_id=(SELECT group_id FROM max_runner_call_groups WHERE run_id=? LIMIT 1)",
                    (self.run_id,),
                ).fetchone()[0],
                PREPARATION_CLAIM_HELD,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM max_runner_invocation_claims WHERE claim_id=?",
                    (self.preparation["claim_id"],),
                ).fetchone()[0],
                "active",
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT released_at FROM max_leases WHERE run_id=?", (self.run_id,)
                ).fetchone()[0]
            )

    def test_05_runner_verifier_accepts_valid_prepared_group(self) -> None:
        issues = self._runner_issues()
        self.assertNotIn("open_group_without_live_invocation_claim", issues)
        self.assertNotIn("prepared_group_missing_handoff", issues)

    def test_06_ordinary_open_group_without_claim_remains_p1(self) -> None:
        with closing(self._rw()) as connection:
            connection.execute(
                "UPDATE max_runner_call_group_current SET lifecycle_state=? WHERE group_id=?",
                (PREPARATION_CLAIM_HELD, self.handoff["call_group_id"]),
            )
            connection.commit()
        self.assertIn("open_group_without_live_invocation_claim", self._runner_issues())

    def test_07_missing_current_projection_fails_closed(self) -> None:
        with closing(self._rw()) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                "DELETE FROM max_runner_preparation_handoff_current WHERE handoff_id=?",
                (self.handoff["handoff_id"],),
            )
            connection.execute(
                "UPDATE max_runner_call_group_current SET lifecycle_state=? WHERE group_id=?",
                (PREPARED, self.handoff["call_group_id"]),
            )
            connection.commit()
        self.assertIn("prepared_group_missing_handoff", self._handoff_issues())

    def test_08_current_projection_tamper_is_detected(self) -> None:
        with closing(self._rw()) as connection:
            connection.execute(
                "UPDATE max_runner_preparation_handoff_current SET current_json=? WHERE handoff_id=?",
                ("{}", self.handoff["handoff_id"]),
            )
            connection.commit()
        self.assertIn("prepared_group_binding_drift", self._handoff_issues())

    def test_09_event_pointer_tamper_is_detected(self) -> None:
        with closing(self._rw()) as connection:
            connection.execute(
                "UPDATE max_runner_preparation_handoff_current SET current_event_hash=? WHERE handoff_id=?",
                ("0" * 64, self.handoff["handoff_id"]),
            )
            connection.commit()
        self.assertIn("prepared_group_binding_drift", self._handoff_issues())

    def test_10_prepared_group_with_live_claim_is_rejected(self) -> None:
        lease = self.repo.acquire_lease(run_id=self.run_id, actor=self.worker, ttl_seconds=60)
        RunnerPersistence(self.repo).claim_invocation(
            run_id=self.run_id,
            actor=self.worker,
            fencing_token=int(lease["fencing_token"]),
            ttl_seconds=60,
        )
        self.assertIn("prepared_group_has_live_claim", self._handoff_issues())

    def test_11_prepared_group_with_active_lease_is_rejected(self) -> None:
        self.repo.acquire_lease(run_id=self.run_id, actor=self.worker, ttl_seconds=60)
        self.assertIn("prepared_group_has_active_lease", self._handoff_issues())

    def test_12_model_send_attempt_is_rejected(self) -> None:
        lease = self.repo.acquire_lease(run_id=self.run_id, actor=self.worker, ttl_seconds=60)
        with closing(self._rw()) as connection:
            logical = connection.execute(
                "SELECT logical_call_id FROM max_model_call_intents WHERE run_id=? LIMIT 1",
                (self.run_id,),
            ).fetchone()[0]
        RunnerPersistence(self.repo).record_attempt(
            run_id=self.run_id,
            logical_call_id=logical,
            stage="dispatching",
            detail={"test": "boundary"},
            actor=self.worker,
            fencing_token=int(lease["fencing_token"]),
        )
        self.assertIn("prepared_group_after_send", self._handoff_issues())

    def test_13_stale_fencing_token_replay_is_rejected(self) -> None:
        with self.assertRaises(PreparationHandoffError):
            self.handoffs.handoff_preparation(**{
                **self._handoff_args(),
                "fencing_token": int(self.preparation["fencing_token"]) - 1,
            })

    def test_14_admin_cannot_impersonate_preparation_worker(self) -> None:
        with self.assertRaises(PreparationHandoffError):
            self.handoffs.handoff_preparation(**{**self._handoff_args(), "worker": self.admin})

    def test_15_snapshot_preview_dns_chain_is_bound(self) -> None:
        with closing(self.repo._connect(read_only=True, verify_schema=False)) as connection:
            chain = self.handoffs._chain(
                connection,
                run_id=self.run_id,
                snapshot_id=self.snapshot["snapshot_id"],
                preview_id=self.preview["preview_id"],
                dns_authority_id=self.dns_request["authority_id"],
                dns_request_id=self.dns_request["request_id"],
            )
        self.assertEqual(chain["preview"]["snapshot_hash"], chain["snapshot"]["snapshot_hash"])

    def test_16_invalid_dns_binding_fails_closed(self) -> None:
        with closing(self.repo._connect(read_only=True, verify_schema=False)) as connection:
            with self.assertRaises(PreparationHandoffError):
                self.handoffs._chain(
                    connection,
                    run_id=self.run_id,
                    snapshot_id=self.snapshot["snapshot_id"],
                    preview_id=self.preview["preview_id"],
                    dns_authority_id=self.dns_request["authority_id"],
                    dns_request_id="not-a-request",
                )

    def test_17_jit_requires_a_fresh_fence(self) -> None:
        lease = self.repo.acquire_lease(run_id=self.run_id, actor=self.worker, ttl_seconds=60)
        claim = RunnerPersistence(self.repo).claim_invocation(
            run_id=self.run_id,
            actor=self.worker,
            fencing_token=int(lease["fencing_token"]),
            ttl_seconds=60,
        )
        with closing(self.repo._connect(read_only=False, verify_schema=False)) as connection:
            from research_kb.max_research.persistence.db import control_transaction

            with control_transaction(connection):
                result = self.handoffs.transition_to_jit_connection(
                    connection,
                    preview_id=self.preview["preview_id"],
                    worker=self.worker,
                    claim_id=claim["claim_id"],
                    fencing_token=int(lease["fencing_token"]),
                    now="2026-08-16T14:00:10.000Z",
                )
        self.assertEqual(result["state"], "JIT_EXECUTING")
        self.assertGreater(int(lease["fencing_token"]), int(self.preparation["fencing_token"]))

    def test_18_jit_rejects_stale_preparation_fence(self) -> None:
        lease = self.repo.acquire_lease(run_id=self.run_id, actor=self.worker, ttl_seconds=60)
        claim = RunnerPersistence(self.repo).claim_invocation(
            run_id=self.run_id,
            actor=self.worker,
            fencing_token=int(lease["fencing_token"]),
            ttl_seconds=60,
        )
        with closing(self.repo._connect(read_only=False, verify_schema=False)) as connection:
            from research_kb.max_research.persistence.db import control_transaction

            with control_transaction(connection):
                with self.assertRaises(PreparationHandoffError):
                    self.handoffs.transition_to_jit_connection(
                        connection,
                        preview_id=self.preview["preview_id"],
                        worker=self.worker,
                        claim_id=claim["claim_id"],
                        fencing_token=int(self.preparation["fencing_token"]),
                        now="2026-08-16T14:00:10.000Z",
                    )

    def test_19_cancel_waiting_handoff_is_terminal_and_verifiable(self) -> None:
        closed = self.handoffs.close_waiting_handoff(
            run_id=self.run_id,
            handoff_id=self.handoff["handoff_id"],
            state="CANCELLED",
            actor=self.admin,
            reason="offline adversarial cancellation",
        )
        self.assertEqual(closed["state"], "CANCELLED")
        self.assertEqual(
            self.handoffs.status(handoff_id=self.handoff["handoff_id"])["state"],
            "CANCELLED",
        )
        self.assertNotIn("open_group_without_live_invocation_claim", self._runner_issues())

    def test_20_expire_waiting_handoff_is_terminal_and_idempotent(self) -> None:
        closed = self.handoffs.close_waiting_handoff(
            run_id=self.run_id,
            handoff_id=self.handoff["handoff_id"],
            state="EXPIRED",
            actor=self.admin,
            reason="offline expiry",
        )
        repeated = self.handoffs.close_waiting_handoff(
            run_id=self.run_id,
            handoff_id=self.handoff["handoff_id"],
            state="EXPIRED",
            actor=self.admin,
            reason="offline expiry",
        )
        self.assertFalse(closed["idempotent"])
        self.assertTrue(repeated["idempotent"])

    def test_21_immutable_handoff_cannot_be_updated(self) -> None:
        with closing(self._rw()) as connection:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(
                    "UPDATE max_runner_preparation_handoffs SET model_identity='tampered' WHERE handoff_id=?",
                    (self.handoff["handoff_id"],),
                )

    def test_22_immutable_handoff_events_cannot_be_updated(self) -> None:
        with closing(self._rw()) as connection:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(
                    "UPDATE max_runner_preparation_handoff_events SET state='FAILED' WHERE handoff_id=?",
                    (self.handoff["handoff_id"],),
                )

    def test_23_backup_restore_verifier_recomputes(self) -> None:
        backup = self.fixture.temp.name + "\\backup.db"
        restored = self.fixture.temp.name + "\\restored.db"
        self.repo.backup(backup)
        result = type(self.repo)(restored, clock=self.fixture.clock).restore(backup)
        self.assertTrue(result["verification"]["ok"])
        self.assertTrue(
            RunnerPersistence(type(self.repo)(restored, clock=self.fixture.clock)).verify_run(
                run_id=self.run_id
            )["ok"]
        )

    def test_24_formal_cli_verify_path_is_hermetic(self) -> None:
        command = [
            sys.executable,
            "-m",
            "research_kb.cli",
            "max",
            "--database",
            str(self.database),
            "verify",
            "--run-id",
            self.run_id,
        ]
        project_root = Path(__file__).parents[1]
        child_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        child_env["PYTHONPATH"] = os.pathsep.join(
            [str(project_root / "src"), child_env.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep)
        result = subprocess.run(
            command,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            env=child_env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'"schema_version": {CONTROL_SCHEMA_VERSION}', result.stdout)
        self.assertNotIn(str(self.database), result.stdout)

    def test_25_start_and_native_approval_counters_are_separate(self) -> None:
        self.fixture.store.create_approval(
            preview_id=self.preview["preview_id"],
            confirmation_phrase=self.fixture.phrase,
            expires_at=self.fixture.expiry,
            actor=self.admin,
        )
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?",
                    (self.run_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_approval_consumptions"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals").fetchone()[0],
                0,
            )

    def test_26_twenty_replays_leave_one_current_handoff(self) -> None:
        def replay(_: int) -> str:
            try:
                return self.handoffs.handoff_preparation(**self._handoff_args())["handoff_id"]
            except PreparationHandoffError as exc:
                return type(exc).__name__

        values = list(ThreadPoolExecutor(max_workers=20).map(replay, range(20)))
        with closing(self._rw()) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM max_runner_preparation_handoffs WHERE call_group_id=?",
                (self.handoff["call_group_id"],),
            ).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertIn(self.handoff["handoff_id"], values)

    def test_27_no_dns_or_provider_side_effects_in_prepared_state(self) -> None:
        with closing(self._rw()) as connection:
            values = [
                connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE run_id=?", (self.run_id,)
                ).fetchone()[0]
                for table in (
                    "max_provider_call_records",
                    "max_provider_call_results",
                    "max_provider_dispatch_attempts",
                    "max_provider_usage_attestations",
                )
            ]
            dns_attempts = connection.execute(
                "SELECT COUNT(*) FROM max_live_canary_native_dns_receipts WHERE preview_id=?",
                (self.preview["preview_id"],),
            ).fetchone()[0]
        self.assertEqual(values, [0, 0, 0, 0])
        # The fixture contains one injected bounded receipt; that is a
        # persisted metadata test fact, not a DNS call or resolver attempt.
        self.assertEqual(dns_attempts, 1)


if __name__ == "__main__":
    unittest.main()
