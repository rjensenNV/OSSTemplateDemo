"""Focused tests for the audited Phase 8 source-only resume control."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from collector.phase8_resume_control import (
    _CHANGED_PATHS,
    _PREDECESSOR_COMMIT,
    _REQUIRED_CONTROL_COMMITS,
    authorize_phase8_scanner_resume_control,
)
from collector.pipeline import (
    PipelineError,
    RunBudgets,
    _network_task_source_sha256,
)
from collector.planner import current_fingerprints
from collector.state import StateDB


RUN_ID = "20260731T125820Z-a530ae81"
PRIOR_NETWORK = "1" * 64
MIGRATION_SHA256 = (
    "fe7849a196e9fb4b4aa12f76e23b6946256f9e7ed647c668c01edada915f5959"
)


class Phase8ScannerResumeControlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = StateDB(self.root / "collector.sqlite3")
        self.fingerprints = current_fingerprints().as_dict()
        self.contract = {
            "run_class": "phase8-cohort-a",
            "release_scope": "partial-portfolio",
            "selected_library_ids": ["cublas"],
            "metadata_batch_size": 50,
            "network_task_source_sha256": PRIOR_NETWORK,
            "scanner_source_migration": {
                "current_network_task_source_sha256": PRIOR_NETWORK,
                "contract_sha256": MIGRATION_SHA256,
            },
        }
        budgets = RunBudgets.reconcile().to_dict()
        budgets["max_wall_seconds"] = 168 * 60 * 60
        self.state.create_run(
            RUN_ID,
            mode="reconcile",
            plan={"execution_contract": self.contract},
            budgets=budgets,
            fingerprints=self.fingerprints,
            status="failed",
        )
        library_fingerprints = dict(
            self.fingerprints["libraries"]["cublas"]
        )
        library_fingerprints["dating"] = self.fingerprints["dating"]
        library_fingerprints["aggregation"] = self.fingerprints[
            "aggregation"
        ]
        self.state.upsert_library(
            "cublas",
            catalog={},
            fingerprints=library_fingerprints,
        )
        for index in range(2):
            repository_id = "R_public_%d" % index
            self.state.upsert_repository({
                "node_id": repository_id,
                "full_name": "public/example-%d" % index,
                "visibility": "public",
                "head_sha": "%x" % (index + 10) * 40,
            })
            task_id = self.state.enqueue_task(
                RUN_ID,
                "scan",
                "task-%d" % index,
                repository_id=repository_id,
                library_id="cublas",
                payload={
                    "full_name": "public/example-%d" % index,
                    "head_sha": "%x" % (index + 10) * 40,
                    "libraries": ["cublas"],
                },
                max_attempts=2,
            )
            if index == 0:
                self.state.connection.execute(
                    """
                    UPDATE tasks SET status='complete',attempts=1,
                        result_json='{}',finished_at=updated_at
                    WHERE task_id=?
                    """,
                    (task_id,),
                )
                self.state.connection.execute(
                    """
                    INSERT INTO scan_attempts(
                        task_id,attempt,run_id,repository_id,task_key,
                        payload_sha256,head_sha,status,retryable,error_code,
                        error_detail,seconds,current_tree_triage_seconds,
                        history_dating_seconds,analysis_seconds,
                        git_subprocess_count,network_clone_count,
                        network_fetch_count,network_materialized_bytes,
                        usage_complete,started_at,finished_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        task_id,
                        1,
                        RUN_ID,
                        repository_id,
                        "task-0",
                        "2" * 64,
                        "a" * 40,
                        "complete",
                        0,
                        None,
                        None,
                        1.0,
                        1.0,
                        0.0,
                        0.0,
                        1,
                        0,
                        0,
                        0,
                        1,
                        "2026-08-01T00:00:00Z",
                        "2026-08-01T00:00:01Z",
                    ),
                )
                self.state.connection.execute(
                    """
                    INSERT INTO scan_results(
                        repository_id,library_id,head_sha,detector_fp,
                        classification,status,evidence_json,scanned_at
                    ) VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        repository_id,
                        "cublas",
                        "a" * 40,
                        self.fingerprints["libraries"]["cublas"]["detector"],
                        "rejected",
                        "clean",
                        "{}",
                        "2026-08-01T00:00:01Z",
                    ),
                )
        self.state.connection.commit()

    def tearDown(self):
        self.state.close()
        self.temporary.cleanup()

    def _audit(self):
        audit = {
            "version": 1,
            "predecessor_source_commit": _PREDECESSOR_COMMIT,
            "successor_source_commit": "e" * 40,
            "required_control_commits": list(_REQUIRED_CONTROL_COMMITS),
            "changed_paths": sorted(_CHANGED_PATHS),
            "prior_network_task_source_sha256": PRIOR_NETWORK,
            "current_network_task_source_sha256": (
                _network_task_source_sha256()
            ),
            "source_audit_sha256": "3" * 64,
        }
        return audit

    def test_control_changes_only_plan_and_its_own_stage(self):
        before_tasks = [
            dict(row)
            for row in self.state.connection.execute(
                "SELECT * FROM tasks ORDER BY task_id"
            )
        ]
        before_attempts = [
            dict(row)
            for row in self.state.connection.execute(
                "SELECT * FROM scan_attempts ORDER BY task_id,attempt"
            )
        ]
        before_results = [
            dict(row)
            for row in self.state.connection.execute(
                "SELECT * FROM scan_results ORDER BY scan_result_id"
            )
        ]
        with (
            mock.patch(
                "collector.phase8_resume_control._TASK_UNIVERSE", 2
            ),
            mock.patch(
                "collector.phase8_resume_control._source_audit",
                return_value=self._audit(),
            ),
            mock.patch(
                "collector.phase8_resume_control."
                "_validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            report = authorize_phase8_scanner_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
                reason="phase8_audited_scanner_resume_control",
            )
        self.assertEqual(0, report["reset_scan_tasks"])
        self.assertEqual(0, report["changed_scan_results"])
        self.assertEqual(0, report["other_budget_changes"])
        self.assertEqual(
            before_tasks,
            [
                dict(row)
                for row in self.state.connection.execute(
                    "SELECT * FROM tasks ORDER BY task_id"
                )
            ],
        )
        self.assertEqual(
            before_attempts,
            [
                dict(row)
                for row in self.state.connection.execute(
                    "SELECT * FROM scan_attempts ORDER BY task_id,attempt"
                )
            ],
        )
        self.assertEqual(
            before_results,
            [
                dict(row)
                for row in self.state.connection.execute(
                    "SELECT * FROM scan_results ORDER BY scan_result_id"
                )
            ],
        )
        run = self.state.connection.execute(
            "SELECT plan_json,budgets_json,fingerprints_json,status FROM runs "
            "WHERE run_id=?",
            (RUN_ID,),
        ).fetchone()
        plan = json.loads(run["plan_json"])
        updated = plan["execution_contract"]
        self.assertEqual(
            _network_task_source_sha256(),
            updated["network_task_source_sha256"],
        )
        self.assertEqual(
            self.contract["scanner_source_migration"],
            updated["scanner_source_migration"],
        )
        self.assertEqual("failed", run["status"])
        self.assertEqual(self.fingerprints, json.loads(run["fingerprints_json"]))
        self.assertEqual(
            RunBudgets.reconcile().to_dict() | {
                "max_wall_seconds": 168 * 60 * 60
            },
            json.loads(run["budgets_json"]),
        )
        stage = self.state.connection.execute(
            "SELECT status,metrics_json FROM stages WHERE run_id=? AND stage=?",
            (RUN_ID, "phase8_scanner_resume_control"),
        ).fetchone()
        self.assertEqual("complete", stage["status"])
        self.assertEqual(
            {
                "changed_scan_results": 0,
                "other_budget_changes": 0,
                "reset_scan_tasks": 0,
            },
            json.loads(stage["metrics_json"]),
        )

    def test_control_rejects_a_changed_task_universe(self):
        original_plan = self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()["plan_json"]
        with (
            mock.patch(
                "collector.phase8_resume_control._TASK_UNIVERSE", 3
            ),
            mock.patch(
                "collector.phase8_resume_control._source_audit",
                return_value=self._audit(),
            ),
        ):
            with self.assertRaisesRegex(PipelineError, "task universe"):
                authorize_phase8_scanner_resume_control(
                    state=self.state,
                    repo_root=self.root,
                    run_id=RUN_ID,
                    reason="phase8_audited_scanner_resume_control",
                )
        current_plan = self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()["plan_json"]
        self.assertEqual(original_plan, current_plan)


if __name__ == "__main__":
    unittest.main()
