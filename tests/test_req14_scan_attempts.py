"""Focused durable scan-attempt ledger tests.

Run: python3.12 -m unittest -v tests.test_req14_scan_attempts
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import tempfile
import unittest
from pathlib import Path

from collector.state import StateDB, canonical_json
from collector.state_migrations import SCHEMA_VERSION


HEAD_SHA = "a" * 40
FULL_USAGE = {
    "seconds": 12.5,
    "current_tree_triage_seconds": 2.0,
    "history_dating_seconds": 7.0,
    "analysis_seconds": 3.5,
    "git_subprocess_count": 8,
    "network_clone_count": 1,
    "network_fetch_count": 2,
    "network_materialized_bytes": 4096,
}


class ScanAttemptStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "state.sqlite3"
        self.state = StateDB(self.path)
        self.state.upsert_repository(
            {
                "node_id": "R_public",
                "full_name": "public/example",
                "visibility": "public",
                "head_sha": HEAD_SHA,
            }
        )

    def tearDown(self):
        self.state.close()
        self.temporary.cleanup()

    def create_run(self, run_id="run", *, mode="reconcile"):
        self.state.create_run(run_id, mode=mode, status="running")

    def enqueue_scan(
        self,
        run_id="run",
        *,
        task_key="scan:public/example",
        repository_id="R_public",
        max_attempts=3,
        payload=None,
    ):
        if payload is None:
            payload = {
                "full_name": "public/example",
                "head_sha": HEAD_SHA,
            }
        return self.state.enqueue_task(
            run_id,
            "scan",
            task_key,
            repository_id=repository_id,
            payload=payload,
            max_attempts=max_attempts,
        )

    def lease(self, task_id, *, worker="worker", now_epoch=100):
        leased = self.state.lease_task_by_id(
            task_id,
            worker=worker,
            lease_seconds=600,
            now_epoch=now_epoch,
        )
        self.assertIsNotNone(leased)
        return leased

    def test_v5_migration_does_not_invent_attempts_for_old_tasks(self):
        self.create_run()
        self.enqueue_scan()
        self.state.close()
        legacy = sqlite3.connect(self.path)
        legacy.execute("DROP TABLE scan_attempts")
        legacy.execute("DELETE FROM schema_migrations WHERE version=5")
        legacy.execute("PRAGMA user_version=4")
        legacy.commit()
        legacy.close()

        self.state = StateDB(self.path)

        self.assertEqual(self.state.schema_version, SCHEMA_VERSION)
        self.assertEqual(SCHEMA_VERSION, 5)
        self.assertEqual(
            self.state.connection.execute(
                "SELECT COUNT(*) FROM scan_attempts"
            ).fetchone()[0],
            0,
        )

    def test_lease_complete_and_fail_share_atomic_attempt_boundaries(self):
        self.create_run()
        task_id = self.enqueue_scan()
        self.state.connection.execute(
            """
            CREATE TEMP TRIGGER reject_scan_attempt_insert
            BEFORE INSERT ON scan_attempts
            BEGIN
                SELECT RAISE(ABORT, 'injected attempt insert failure');
            END
            """
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.state.lease_task_by_id(
                task_id, worker="worker", now_epoch=100
            )
        task = self.state.connection.execute(
            "SELECT status, attempts FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        self.assertEqual((task["status"], task["attempts"]), ("pending", 0))
        self.state.connection.execute("DROP TRIGGER reject_scan_attempt_insert")

        self.lease(task_id)
        self.state.connection.execute(
            """
            CREATE TEMP TRIGGER reject_scan_attempt_complete
            BEFORE UPDATE OF status ON scan_attempts
            WHEN NEW.status='complete'
            BEGIN
                SELECT RAISE(ABORT, 'injected attempt completion failure');
            END
            """
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.state.complete_task(
                task_id,
                worker="worker",
                result=FULL_USAGE,
                now_epoch=101,
            )
        task = self.state.connection.execute(
            "SELECT status FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        attempt = self.state.connection.execute(
            "SELECT status FROM scan_attempts WHERE task_id=?",
            (str(task_id),),
        ).fetchone()
        self.assertEqual(task["status"], "running")
        self.assertEqual(attempt["status"], "running")
        self.state.connection.execute(
            "DROP TRIGGER reject_scan_attempt_complete"
        )

        self.state.connection.execute(
            """
            CREATE TEMP TRIGGER reject_scan_attempt_fail
            BEFORE UPDATE OF status ON scan_attempts
            WHEN NEW.status='failed'
            BEGIN
                SELECT RAISE(ABORT, 'injected attempt failure failure');
            END
            """
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.state.fail_task(
                task_id,
                worker="worker",
                error_code="fixture_failure",
                result=FULL_USAGE,
                retry=False,
                now_epoch=101,
            )
        task = self.state.connection.execute(
            "SELECT status FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        attempt = self.state.connection.execute(
            "SELECT status FROM scan_attempts WHERE task_id=?",
            (str(task_id),),
        ).fetchone()
        self.assertEqual(task["status"], "running")
        self.assertEqual(attempt["status"], "running")

    def test_attempt_identity_metrics_and_aggregate_survive_retry(self):
        self.create_run()
        payload = {
            "repo_node_id": "R_public",
            "head_sha": HEAD_SHA,
            "full_name": "public/example",
        }
        task_id = self.enqueue_scan(
            repository_id=None,
            payload=payload,
            max_attempts=2,
        )
        first = self.lease(task_id, worker="worker-a")
        self.assertEqual(first["attempts"], 1)
        first_status = self.state.fail_task(
            task_id,
            worker="worker-a",
            error_code="temporary_clone_failure",
            result={**FULL_USAGE, "error": "temporary failure"},
            retry=True,
            now_epoch=101,
        )
        self.assertEqual(first_status, "pending")

        second = self.lease(task_id, worker="worker-b", now_epoch=102)
        self.assertEqual(second["attempts"], 2)
        second_usage = {
            **FULL_USAGE,
            "seconds": 4.0,
            "network_clone_count": 0,
            "network_fetch_count": 1,
            "network_materialized_bytes": 1024,
        }
        self.state.complete_task(
            task_id,
            worker="worker-b",
            result={"status": "clean", **second_usage},
            now_epoch=103,
        )

        attempts = [
            dict(row)
            for row in self.state.connection.execute(
                """
                SELECT * FROM scan_attempts
                WHERE task_id=? ORDER BY attempt
                """,
                (str(task_id),),
            )
        ]
        self.assertEqual(
            [(row["attempt"], row["status"], row["retryable"])
             for row in attempts],
            [(1, "failed", 1), (2, "complete", 0)],
        )
        self.assertTrue(all(row["usage_complete"] == 1 for row in attempts))
        self.assertTrue(all(row["repository_id"] == "R_public"
                            for row in attempts))
        self.assertTrue(all(row["head_sha"] == HEAD_SHA for row in attempts))
        self.assertEqual(
            attempts[0]["payload_sha256"],
            hashlib.sha256(
                canonical_json(payload).encode("utf-8")
            ).hexdigest(),
        )
        summary = json.loads(
            self.state.connection.execute(
                "SELECT result_json FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()[0]
        )
        self.assertEqual(summary["status"], "clean")
        self.assertEqual(summary["seconds"], 4.0)

        usage = self.state.scan_attempt_usage("run")
        self.assertEqual(usage["attempt_count"], 2)
        self.assertEqual(usage["failed_attempts"], 1)
        self.assertEqual(usage["complete_attempts"], 1)
        self.assertEqual(usage["seconds"], 16.5)
        self.assertEqual(usage["network_clone_count"], 1)
        self.assertEqual(usage["network_fetch_count"], 3)
        self.assertEqual(usage["network_materialized_bytes"], 5120)

    def test_finished_attempt_charge_survives_pre_verdict_crash(self):
        self.create_run()
        task_id = self.enqueue_scan(max_attempts=2)
        self.lease(task_id)
        result = {"status": "clean", **FULL_USAGE}

        self.state.record_scan_attempt_result(
            task_id,
            worker="worker",
            status="complete",
            retryable=False,
            error_code=None,
            result=result,
            now_epoch=101,
        )
        # Repeating the exact checkpoint is idempotent; changing its charge is
        # refused before the task verdict can commit.
        self.state.record_scan_attempt_result(
            task_id,
            worker="worker",
            status="complete",
            retryable=False,
            error_code=None,
            result=result,
            now_epoch=101,
        )
        with self.assertRaisesRegex(
            RuntimeError, "durable scan attempt result changed"
        ):
            self.state.record_scan_attempt_result(
                task_id,
                worker="worker",
                status="complete",
                retryable=False,
                error_code=None,
                result={**result, "network_materialized_bytes": 1},
                now_epoch=101,
            )

        task = self.state.connection.execute(
            "SELECT status, attempts FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        self.assertEqual((task["status"], task["attempts"]), ("running", 1))
        usage = self.state.scan_attempt_usage("run")
        self.assertEqual(usage["attempt_count"], 1)
        self.assertEqual(usage["complete_attempts"], 1)
        self.assertEqual(usage["network_materialized_bytes"], 4096)

        # Simulate a coordinator death after charging the worker result but
        # before scan_results/task completion. The verdict is safely retried,
        # and the first attempt remains charged exactly once.
        self.state.finish_run("run", status="failed")
        self.assertEqual(
            self.state.resume_compatible_run(mode="reconcile"), "run"
        )
        resumed = self.state.connection.execute(
            "SELECT status, attempts FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        self.assertEqual(
            (resumed["status"], resumed["attempts"]), ("pending", 1)
        )
        self.assertEqual(
            self.lease(task_id, worker="retry-worker", now_epoch=102)[
                "attempts"
            ],
            2,
        )
        self.state.complete_task(
            task_id,
            worker="retry-worker",
            result=result,
            now_epoch=103,
        )
        usage = self.state.scan_attempt_usage("run")
        self.assertEqual(usage["attempt_count"], 2)
        self.assertEqual(usage["complete_attempts"], 2)
        self.assertEqual(usage["network_materialized_bytes"], 8192)

    def test_attempt_checkpoint_rejects_invalid_usage_and_terminal_matrix(self):
        self.create_run()
        task_id = self.enqueue_scan()
        self.lease(task_id)
        invalid_results = []
        missing = dict(FULL_USAGE)
        missing.pop("network_fetch_count")
        invalid_results.append(missing)
        for value in (-1, True, math.nan, math.inf):
            invalid_results.append({
                **FULL_USAGE,
                "network_materialized_bytes": value,
            })
        for result in invalid_results:
            with self.subTest(result=result):
                with self.assertRaises((TypeError, ValueError)):
                    self.state.record_scan_attempt_result(
                        task_id,
                        worker="worker",
                        status="complete",
                        retryable=False,
                        error_code=None,
                        result=result,
                        now_epoch=101,
                    )
        invalid_terminals = (
            ("complete", True, None),
            ("complete", False, "impossible_error"),
            ("failed", False, None),
        )
        for status, retryable, error_code in invalid_terminals:
            with self.subTest(
                status=status,
                retryable=retryable,
                error_code=error_code,
            ):
                with self.assertRaises(ValueError):
                    self.state.record_scan_attempt_result(
                        task_id,
                        worker="worker",
                        status=status,
                        retryable=retryable,
                        error_code=error_code,
                        result=FULL_USAGE,
                        now_epoch=101,
                    )
        task = self.state.connection.execute(
            "SELECT status FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        attempt = self.state.connection.execute(
            "SELECT status, usage_complete FROM scan_attempts WHERE task_id=?",
            (str(task_id),),
        ).fetchone()
        self.assertEqual(task["status"], "running")
        self.assertEqual(
            (attempt["status"], attempt["usage_complete"]), ("running", 0)
        )

    def test_attempt_checkpoint_rejects_invalid_lease_and_missing_ledger(self):
        self.create_run()
        task_id = self.enqueue_scan()
        self.lease(task_id)
        for worker, now_epoch in (("wrong-worker", 101), ("worker", 701)):
            with self.subTest(worker=worker, now_epoch=now_epoch):
                with self.assertRaisesRegex(RuntimeError, "lease"):
                    self.state.record_scan_attempt_result(
                        task_id,
                        worker=worker,
                        status="complete",
                        retryable=False,
                        error_code=None,
                        result=FULL_USAGE,
                        now_epoch=now_epoch,
                    )

        network_task = self.state.enqueue_task(
            "run", "metadata", "metadata-task"
        )
        self.assertIsNotNone(
            self.state.lease_task_by_id(
                network_task,
                worker="metadata-worker",
                now_epoch=100,
            )
        )
        with self.assertRaisesRegex(RuntimeError, "scan task lease"):
            self.state.record_scan_attempt_result(
                network_task,
                worker="metadata-worker",
                status="complete",
                retryable=False,
                error_code=None,
                result=FULL_USAGE,
                now_epoch=101,
            )

        self.state.connection.execute(
            "DELETE FROM scan_attempts WHERE task_id=?", (str(task_id),)
        )
        with self.assertRaisesRegex(RuntimeError, "durable ledger"):
            self.state.record_scan_attempt_result(
                task_id,
                worker="worker",
                status="complete",
                retryable=False,
                error_code=None,
                result=FULL_USAGE,
                now_epoch=101,
            )
        task = self.state.connection.execute(
            "SELECT status, attempts FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        self.assertEqual((task["status"], task["attempts"]), ("running", 1))

    def test_attempt_checkpoint_update_failure_rolls_back(self):
        self.create_run()
        task_id = self.enqueue_scan()
        self.lease(task_id)
        self.state.connection.execute(
            """
            CREATE TEMP TRIGGER reject_durable_attempt_checkpoint
            BEFORE UPDATE OF status ON scan_attempts
            WHEN NEW.status='complete'
            BEGIN
                SELECT RAISE(ABORT, 'injected durable checkpoint failure');
            END
            """
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.state.record_scan_attempt_result(
                task_id,
                worker="worker",
                status="complete",
                retryable=False,
                error_code=None,
                result=FULL_USAGE,
                now_epoch=101,
            )
        attempt = self.state.connection.execute(
            "SELECT status, usage_complete FROM scan_attempts WHERE task_id=?",
            (str(task_id),),
        ).fetchone()
        self.assertEqual(
            (attempt["status"], attempt["usage_complete"]), ("running", 0)
        )

    def test_pre_verdict_failure_retryability_survives_recovery(self):
        self.create_run()
        retryable_task = self.enqueue_scan(
            task_key="retryable", max_attempts=2
        )
        self.lease(retryable_task)
        self.state.record_scan_attempt_result(
            retryable_task,
            worker="worker",
            status="failed",
            retryable=True,
            error_code="temporary_clone_failure",
            result=FULL_USAGE,
            now_epoch=101,
        )
        self.state.finish_run("run", status="failed")
        self.assertEqual(
            self.state.resume_compatible_run(mode="reconcile"), "run"
        )
        retryable = self.state.connection.execute(
            "SELECT status, error_code FROM tasks WHERE task_id=?",
            (retryable_task,),
        ).fetchone()
        self.assertEqual(
            (retryable["status"], retryable["error_code"]),
            ("pending", "temporary_clone_failure"),
        )
        self.lease(retryable_task, worker="retry-worker", now_epoch=102)
        self.state.complete_task(
            retryable_task,
            worker="retry-worker",
            result=FULL_USAGE,
            now_epoch=103,
        )
        usage = self.state.scan_attempt_usage("run")
        self.assertEqual(usage["attempt_count"], 2)
        self.assertEqual(usage["failed_attempts"], 1)
        self.assertEqual(usage["complete_attempts"], 1)
        self.assertEqual(usage["network_materialized_bytes"], 8192)

        self.state.finish_run("run", status="complete")
        self.create_run("nonretryable")
        terminal_task = self.enqueue_scan(
            "nonretryable", task_key="terminal", max_attempts=2
        )
        self.lease(terminal_task, worker="terminal-worker")
        self.state.record_scan_attempt_result(
            terminal_task,
            worker="terminal-worker",
            status="failed",
            retryable=False,
            error_code="git_materialization_budget_exceeded",
            result=FULL_USAGE,
            now_epoch=101,
        )
        self.assertEqual(self.state.recover_stale_tasks(now_epoch=701), 1)
        terminal = self.state.connection.execute(
            "SELECT status, error_code FROM tasks WHERE task_id=?",
            (terminal_task,),
        ).fetchone()
        self.assertEqual(
            (terminal["status"], terminal["error_code"]),
            ("failed", "git_materialization_budget_exceeded"),
        )
        self.state.finish_run("nonretryable", status="failed")
        self.assertEqual(
            self.state.resume_compatible_run(mode="reconcile"),
            "nonretryable",
        )
        terminal = self.state.connection.execute(
            "SELECT status, error_code FROM tasks WHERE task_id=?",
            (terminal_task,),
        ).fetchone()
        self.assertEqual(
            (terminal["status"], terminal["error_code"]),
            ("failed", "git_materialization_budget_exceeded"),
        )
        self.assertIsNone(
            self.state.lease_task_by_id(
                terminal_task,
                worker="unsafe-retry",
                now_epoch=702,
            )
        )

    def test_stale_and_abandoned_attempts_are_durable_interruptions(self):
        self.create_run()
        stale_task = self.enqueue_scan(task_key="stale")
        self.lease(stale_task, worker="stale-worker", now_epoch=100)
        self.assertEqual(self.state.recover_stale_tasks(now_epoch=701), 1)
        stale_attempt = self.state.connection.execute(
            "SELECT * FROM scan_attempts WHERE task_id=?",
            (str(stale_task),),
        ).fetchone()
        self.assertEqual(stale_attempt["status"], "interrupted")
        self.assertEqual(stale_attempt["retryable"], 1)
        self.assertEqual(stale_attempt["usage_complete"], 0)
        self.assertEqual(stale_attempt["error_code"], "lease_expired")
        self.assertIsNone(
            self.state.lease_task_by_id(
                stale_task,
                worker="unsafe-retry",
                lease_seconds=600,
                now_epoch=702,
            )
        )
        usage = self.state.scan_attempt_usage("run")
        self.assertEqual(usage["attempt_count"], 1)
        self.assertEqual(usage["exact_attempt_count"], 0)
        self.assertEqual(usage["irreconstructible_attempt_count"], 1)
        self.assertEqual(usage["network_fetch_unknown_attempt_count"], 1)
        self.assertEqual(usage["network_fetch_count"], 0)
        self.state.finish_run("run", status="failed")
        self.assertEqual(
            self.state.resume_compatible_run(mode="reconcile"),
            "run",
        )
        stale_task_row = self.state.connection.execute(
            "SELECT status, error_code FROM tasks WHERE task_id=?",
            (stale_task,),
        ).fetchone()
        self.assertEqual(stale_task_row["status"], "pending")
        self.assertEqual(
            stale_task_row["error_code"], "lease_expired"
        )
        self.state.abandon_run("run", reason="fixture_closed")

        self.create_run("abandon")
        abandoned_task = self.enqueue_scan(
            "abandon", task_key="abandoned"
        )
        self.lease(abandoned_task, worker="dead-worker")
        self.state.abandon_run("abandon", reason="operator_reviewed")
        abandoned_attempt = self.state.connection.execute(
            "SELECT * FROM scan_attempts WHERE task_id=?",
            (str(abandoned_task),),
        ).fetchone()
        self.assertEqual(abandoned_attempt["status"], "interrupted")
        self.assertEqual(abandoned_attempt["retryable"], 0)
        self.assertEqual(abandoned_attempt["usage_complete"], 0)
        self.assertEqual(
            abandoned_attempt["error_code"],
            "run_abandoned:operator_reviewed",
        )

    def test_active_attempt_does_not_block_other_scan_workers(self):
        self.create_run()
        first_task = self.enqueue_scan(task_key="first")
        second_task = self.enqueue_scan(task_key="second")

        self.assertIsNotNone(
            self.state.lease_task_by_id(
                first_task,
                worker="worker-a",
                lease_seconds=600,
                now_epoch=100,
            )
        )
        self.assertIsNotNone(
            self.state.lease_task_by_id(
                second_task,
                worker="worker-b",
                lease_seconds=600,
                now_epoch=100,
            )
        )
        attempts = self.state.connection.execute(
            """
            SELECT task_id, status, usage_complete
            FROM scan_attempts ORDER BY task_id
            """
        ).fetchall()
        self.assertEqual(len(attempts), 2)
        self.assertTrue(all(row["status"] == "running" for row in attempts))
        self.assertTrue(
            all(row["usage_complete"] == 0 for row in attempts)
        )

    def test_resume_retries_charged_unknown_and_refuses_nonretryable_attempts(self):
        self.create_run("unknown")
        unknown_task = self.enqueue_scan(
            "unknown", task_key="unknown", max_attempts=2
        )
        self.lease(unknown_task, worker="dead-worker")
        self.state.finish_run("unknown", status="failed")

        resumed = self.state.resume_compatible_run(mode="reconcile")

        self.assertEqual(resumed, "unknown")
        unknown = self.state.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (unknown_task,)
        ).fetchone()
        self.assertEqual(unknown["status"], "pending")
        self.assertEqual(
            unknown["error_code"], "coordinator_interrupted"
        )
        interrupted = self.state.connection.execute(
            "SELECT * FROM scan_attempts WHERE task_id=?",
            (str(unknown_task),),
        ).fetchone()
        self.assertEqual(interrupted["status"], "interrupted")
        self.assertEqual(interrupted["usage_complete"], 0)

        self.state.abandon_run("unknown", reason="fixture_closed")
        self.create_run("nonretryable")
        failed_task = self.enqueue_scan(
            "nonretryable", task_key="nonretryable", max_attempts=1
        )
        self.lease(failed_task)
        self.state.fail_task(
            failed_task,
            worker="worker",
            error_code="invalid_repository",
            result={**FULL_USAGE, "error": "invalid repository"},
            retry=False,
            now_epoch=101,
        )
        self.state.finish_run("nonretryable", status="failed")

        resumed = self.state.resume_compatible_run(mode="reconcile")

        self.assertEqual(resumed, "nonretryable")
        failed = self.state.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (failed_task,)
        ).fetchone()
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["attempts"], 1)
        self.assertEqual(failed["max_attempts"], 1)
        self.assertEqual(failed["error_code"], "invalid_repository")

        changed = self.state.reset_failed_tasks(
            "nonretryable", reason="operator_reviewed"
        )
        self.assertEqual(changed, 1)
        reviewed = self.state.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (failed_task,)
        ).fetchone()
        self.assertEqual(reviewed["status"], "pending")
        self.assertEqual(reviewed["attempts"], 1)
        self.assertEqual(reviewed["max_attempts"], 2)
        self.assertEqual(
            reviewed["error_code"], "reviewed_retry:operator_reviewed"
        )
        self.assertEqual(
            self.lease(failed_task, worker="reviewed-worker")["attempts"],
            2,
        )

    def test_resume_can_lease_a_charged_unknown_interrupted_attempt(self):
        for lease_by_id in (False, True):
            with self.subTest(lease_by_id=lease_by_id):
                run_id = "unknown-%s" % ("exact" if lease_by_id else "next")
                self.create_run(run_id)
                task_id = self.enqueue_scan(
                    run_id, task_key=run_id, max_attempts=2
                )
                self.lease(task_id, worker="dead-worker")
                self.state.finish_run(run_id, status="failed")

                self.assertEqual(
                    self.state.resume_compatible_run(mode="reconcile"),
                    run_id,
                )
                if lease_by_id:
                    leased = self.state.lease_task_by_id(
                        task_id,
                        worker="recovery-worker",
                        lease_seconds=600,
                        now_epoch=200,
                    )
                else:
                    leased = self.state.lease_task(
                        run_id=run_id,
                        worker="recovery-worker",
                        lease_seconds=600,
                        stages=("scan",),
                        now_epoch=200,
                    )
                self.assertIsNotNone(leased)
                self.assertEqual(leased["task_id"], task_id)
                self.assertEqual(leased["attempts"], 2)
                attempts = self.state.connection.execute(
                    """
                    SELECT attempt,status,retryable,usage_complete
                    FROM scan_attempts WHERE task_id=? ORDER BY attempt
                    """,
                    (str(task_id),),
                ).fetchall()
                self.assertEqual(
                    [tuple(row) for row in attempts],
                    [
                        (1, "interrupted", 1, 0),
                        (2, "running", None, 0),
                    ],
                )
                self.state.abandon_run(
                    run_id, reason="fixture_closed"
                )

    def test_incomplete_nonretryable_attempt_still_blocks_every_lease(self):
        self.create_run()
        task_id = self.enqueue_scan(max_attempts=2)
        self.lease(task_id, worker="dead-worker")
        with self.state.transaction(immediate=True):
            self.state.connection.execute(
                """
                UPDATE scan_attempts
                SET status='interrupted',retryable=0,
                    error_code='operator_refused',finished_at='fixture'
                WHERE task_id=? AND attempt=1
                """,
                (str(task_id),),
            )
            self.state.connection.execute(
                """
                UPDATE tasks SET status='pending',lease_owner=NULL,
                    lease_expires_at=NULL WHERE task_id=?
                """,
                (task_id,),
            )

        self.assertIsNone(
            self.state.lease_task_by_id(
                task_id,
                worker="recovery-worker",
                lease_seconds=600,
                now_epoch=200,
            )
        )
        self.assertIsNone(
            self.state.lease_task(
                run_id="run",
                worker="recovery-worker",
                lease_seconds=600,
                stages=("scan",),
                now_epoch=200,
            )
        )

    def test_resume_preserves_a_hashed_phase8_issue_retry(self):
        self.create_run()
        task_id = self.enqueue_scan(task_key="typed", max_attempts=1)
        self.lease(task_id)
        self.state.fail_task(
            task_id,
            worker="worker",
            error_code="detector_error",
            result={**FULL_USAGE, "error": "typed cache incident"},
            retry=False,
            now_epoch=101,
        )
        selected = [{
            "task_id": task_id,
            "task_key": "typed",
            "repository_id": "R_public",
            "attempts": 1,
            "max_attempts": 1,
            "prior_error_code": "detector_error",
            "normalized_error_code": "repository_cache_integrity",
            "policy": "exact_runtime_reclassification",
        }]
        selection_sha256 = hashlib.sha256(
            canonical_json(selected).encode("utf-8")
        ).hexdigest()
        with self.state.transaction(immediate=True):
            self.state.connection.execute(
                """
                UPDATE tasks SET status='pending',max_attempts=2,
                    error_code='issue_retry:exact_runtime_reclassification',
                    finished_at=NULL WHERE task_id=?
                """,
                (task_id,),
            )
        self.state.update_stage(
            "run",
            "phase8_issue_retry",
            status="complete",
            checkpoint={
                "selection_sha256": selection_sha256,
                "selected_tasks": selected,
                "reset_task_count": 1,
                "other_budget_changes": 0,
            },
        )
        self.state.finish_run("run", status="failed")
        self.assertEqual(
            self.state.resume_compatible_run(mode="reconcile"),
            "run",
        )
        task = self.state.connection.execute(
            "SELECT status,error_code FROM tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        self.assertEqual(task["status"], "pending")
        self.assertEqual(
            task["error_code"],
            "issue_retry:exact_runtime_reclassification",
        )

    def test_scanner_migration_preserves_pre_migration_retry_key(self):
        self.create_run()
        task_id = self.enqueue_scan(task_key="old-task", max_attempts=1)
        self.lease(task_id)
        self.state.fail_task(
            task_id,
            worker="worker",
            error_code="detector_error",
            result={**FULL_USAGE, "error": "typed cache incident"},
            retry=False,
            now_epoch=101,
        )
        selected = [{
            "task_id": task_id,
            "task_key": "old-task",
            "repository_id": "R_public",
            "attempts": 1,
            "max_attempts": 1,
            "prior_error_code": "detector_error",
            "normalized_error_code": "repository_cache_integrity",
            "policy": "exact_runtime_reclassification",
        }]
        selection_sha256 = hashlib.sha256(
            canonical_json(selected).encode("utf-8")
        ).hexdigest()
        migration = {
            "version": 1,
            "task_universe_count": 1,
            "migrated_scan_task_key_count": 1,
        }
        migration["contract_sha256"] = hashlib.sha256(
            canonical_json(migration).encode("utf-8")
        ).hexdigest()
        with self.state.transaction(immediate=True):
            self.state.connection.execute(
                """
                UPDATE tasks SET status='pending',task_key='new-task',
                    max_attempts=2,
                    error_code='issue_retry:exact_runtime_reclassification',
                    finished_at=NULL WHERE task_id=?
                """,
                (task_id,),
            )
            self.state.connection.execute(
                "UPDATE runs SET plan_json=? WHERE run_id='run'",
                (canonical_json({
                    "execution_contract": {
                        "scanner_source_migration": migration,
                    }
                }),),
            )
        self.state.update_stage(
            "run",
            "phase8_issue_retry",
            status="complete",
            checkpoint={
                "selection_sha256": selection_sha256,
                "selected_tasks": selected,
                "reset_task_count": 1,
                "other_budget_changes": 0,
            },
        )
        self.state.update_stage(
            "run",
            "phase8_scanner_source_migration",
            status="complete",
            checkpoint={"migration": migration},
        )
        self.state.finish_run("run", status="failed")
        self.assertEqual(
            self.state.resume_compatible_run(
                mode="reconcile",
                execution_contract={
                    "scanner_source_migration": migration,
                },
            ),
            "run",
        )
        task = self.state.connection.execute(
            "SELECT status,error_code,task_key FROM tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        self.assertEqual("pending", task["status"])
        self.assertEqual("new-task", task["task_key"])
        self.assertEqual(
            "issue_retry:exact_runtime_reclassification",
            task["error_code"],
        )

    def test_resume_preserves_only_certified_scanner_source_retry(self):
        self.create_run()
        task_id = self.enqueue_scan(task_key="source-fixed", max_attempts=1)
        self.lease(task_id)
        self.state.fail_task(
            task_id,
            worker="worker",
            error_code="invalid_notebook",
            result={**FULL_USAGE, "error": "generated notebook"},
            retry=False,
            now_epoch=101,
        )
        selected = [{
            "task_id": task_id,
            "task_key": "source-fixed",
            "prior_attempts": 1,
            "target_max_attempts": 2,
            "policy": "audited_scanner_source_migration",
        }]
        selected.extend({
            "task_id": task_id + index,
            "task_key": "other-%d" % index,
            "prior_attempts": 1,
            "target_max_attempts": 2,
            "policy": "audited_scanner_source_migration",
        } for index in range(1, 4))
        selection_sha256 = hashlib.sha256(
            canonical_json(selected).encode("utf-8")
        ).hexdigest()
        with self.state.transaction(immediate=True):
            self.state.connection.execute(
                """
                UPDATE tasks SET status='pending',max_attempts=2,
                    error_code=(
                      'issue_retry:audited_scanner_source_migration'
                    ),finished_at=NULL WHERE task_id=?
                """,
                (task_id,),
            )
        self.state.update_stage(
            "run",
            "phase8_scanner_source_issue_retry",
            status="complete",
            checkpoint={
                "version": 1,
                "scanner_migration_contract_sha256": "a" * 64,
                "selection_sha256": selection_sha256,
                "selected_tasks": selected,
                "reset_task_count": 4,
                "task_universe_count": 4,
                "other_budget_changes": 0,
            },
        )
        self.state.finish_run("run", status="failed")
        self.assertEqual(
            self.state.resume_compatible_run(mode="reconcile"),
            "run",
        )
        task = self.state.connection.execute(
            "SELECT status,error_code FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        self.assertEqual("pending", task["status"])
        self.assertEqual(
            "issue_retry:audited_scanner_source_migration",
            task["error_code"],
        )

        self.state.finish_run("run", status="failed")
        checkpoint = self.state.connection.execute(
            """
            SELECT checkpoint_json FROM stages
            WHERE run_id='run'
              AND stage='phase8_scanner_source_issue_retry'
            """
        ).fetchone()
        document = json.loads(checkpoint["checkpoint_json"])
        document["selection_sha256"] = "b" * 64
        self.state.update_stage(
            "run",
            "phase8_scanner_source_issue_retry",
            status="complete",
            checkpoint=document,
        )
        self.assertEqual(
            self.state.resume_compatible_run(mode="reconcile"),
            "run",
        )
        task = self.state.connection.execute(
            "SELECT status,error_code FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        self.assertEqual("failed", task["status"])
        self.assertEqual("invalid_notebook", task["error_code"])

    def test_partial_usage_fails_closed_without_blocking_task_journal(self):
        self.create_run()
        task_id = self.enqueue_scan()
        self.lease(task_id)
        partial = dict(FULL_USAGE)
        partial.pop("network_fetch_count")
        self.state.complete_task(
            task_id,
            worker="worker",
            result={"status": "clean", **partial},
            now_epoch=101,
        )

        task = self.state.connection.execute(
            "SELECT status, result_json FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        attempt = self.state.connection.execute(
            "SELECT * FROM scan_attempts WHERE task_id=?", (str(task_id),)
        ).fetchone()
        self.assertEqual(task["status"], "complete")
        self.assertEqual(json.loads(task["result_json"])["status"], "clean")
        self.assertEqual(attempt["status"], "complete")
        self.assertEqual(attempt["usage_complete"], 0)
        self.assertIsNone(attempt["network_fetch_count"])
        with self.assertRaisesRegex(RuntimeError, "incomplete or unknown"):
            self.state.scan_attempt_usage("run")

    def test_checkpoint_includes_and_sanitizes_scan_attempts(self):
        self.create_run()
        task_id = self.enqueue_scan()
        self.lease(task_id)
        self.state.fail_task(
            task_id,
            worker="worker",
            error_code="fixture_failure",
            result={
                **FULL_USAGE,
                "error": "private/repository leaked in diagnostic",
            },
            retry=False,
            now_epoch=101,
        )

        local = self.state.connection.execute(
            "SELECT error_detail FROM scan_attempts WHERE task_id=?",
            (str(task_id),),
        ).fetchone()[0]
        checkpoint = self.state.checkpoint_document()
        attempt_rows = checkpoint["tables"]["scan_attempts"]["rows"]
        self.assertEqual(len(attempt_rows), 1)
        self.assertIn("private/repository", local)
        self.assertNotIn(
            "private/repository", attempt_rows[0]["error_detail"]
        )
        self.assertIn("[REDACTED REPOSITORY]",
                      attempt_rows[0]["error_detail"])
        checkpoint_bytes = self.state.checkpoint_bytes()
        self.assertNotIn(b"private/repository", checkpoint_bytes)

        unsafe = json.loads(json.dumps(checkpoint))
        unsafe["tables"]["scan_attempts"]["rows"][0][
            "error_detail"
        ] = "private/repository leaked in diagnostic"
        with self.assertRaisesRegex(
            ValueError, "unadmitted task identity"
        ):
            self.state._validate_checkpoint(unsafe)

        checkpoint_path = Path(self.temporary.name) / "checkpoint.json"
        checkpoint_path.write_bytes(checkpoint_bytes)
        restored_path = Path(self.temporary.name) / "restored.sqlite3"
        with StateDB(restored_path) as restored:
            restored.import_checkpoint(checkpoint_path)
            restored_attempt = restored.connection.execute(
                "SELECT * FROM scan_attempts"
            ).fetchone()
            self.assertIsNotNone(restored_attempt)
            self.assertNotIn(
                "private/repository", restored_attempt["error_detail"]
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
