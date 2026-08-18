"""Focused tests for the owner-authorized Phase 8 scan-tail boundary."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from collector.fingerprints import canonical_json
from collector.github_client import RepositoryMetadata
from collector.phase8_tail_control import (
    _CHANGED_PATHS,
    _DOWNSTREAM_CHANGED_PATHS,
    _DOWNSTREAM_PREDECESSOR_COMMIT,
    _GRAPHQL_CHANGED_PATHS,
    _GRAPHQL_PREDECESSOR_COMMIT,
    _PREDECESSOR_COMMIT,
    _RESUME_CHANGED_PATHS,
    _RESUME_PREDECESSOR_COMMIT,
    _VISIBILITY_CHANGED_PATHS,
    _VISIBILITY_PREDECESSOR_COMMIT,
    _VISIBILITY_REJECTION_CHANGED_PATHS,
    _VISIBILITY_REJECTION_PREDECESSOR_COMMIT,
    _VISIBILITY_REFRESH_CHANGED_PATHS,
    _VISIBILITY_REFRESH_PREDECESSOR_COMMIT,
    _VISIBILITY_BUDGET_CHANGED_PATHS,
    _VISIBILITY_BUDGET_PREDECESSOR_COMMIT,
    _VISIBILITY_TRANSPORT_RETRY_CHANGED_PATHS,
    _VISIBILITY_TRANSPORT_RETRY_PREDECESSOR_COMMIT,
    _VISIBILITY_EPOCH_RECOVERY_CHANGED_PATHS,
    _VISIBILITY_EPOCH_RECOVERY_PREDECESSOR_COMMIT,
    _POST_REFRESH_PRIVACY_CHANGED_PATHS,
    _POST_REFRESH_PRIVACY_PREDECESSOR_COMMIT,
    _FINAL_VISIBILITY_PRIVACY_CHANGED_PATHS,
    _FINAL_VISIBILITY_PRIVACY_PREDECESSOR_COMMIT,
    _VISIBILITY_SET_CHANGED_PATHS,
    _VISIBILITY_SET_PREDECESSOR_COMMIT,
    authorize_phase8_scan_tail_deferral,
    authorize_phase8_downstream_resume_control,
    authorize_phase8_graphql_resume_control,
    authorize_phase8_scan_tail_resume_control,
    authorize_phase8_visibility_resume_control,
    authorize_phase8_visibility_rejection_resume_control,
    authorize_phase8_visibility_refresh_resume_control,
    authorize_phase8_visibility_budget_resume_control,
    authorize_phase8_visibility_transport_retry_control,
    authorize_phase8_visibility_epoch_recovery_control,
    authorize_phase8_post_refresh_privacy_control,
)
from collector.pipeline import (
    PipelineError,
    RunBudgets,
    _apply_phase8_scan_tail_deferral,
    _validate_phase8_downstream_resume_control,
    _validate_phase8_graphql_resume_control,
    _validate_phase8_fresh_candidate_deferral_control,
    _validate_phase8_privacy_resume_control,
    _validate_phase8_visibility_resume_control,
    _validate_phase8_visibility_rejection_resume_control,
    _validate_phase8_visibility_refresh_resume_control,
    _validate_phase8_visibility_budget_resume_control,
    _validate_phase8_visibility_transport_retry_control,
    _validate_phase8_visibility_epoch_recovery_control,
    _validate_phase8_post_refresh_privacy_control,
    _validate_phase8_final_visibility_privacy_control,
    _validate_phase8_visibility_set_resume_control,
)
from collector.planner import current_fingerprints
from collector.publish_v2 import PublicationError, stage_v2
from collector.state import StateDB


RUN_ID = "20260731T125820Z-a530ae81"
PRIOR_NETWORK = "1" * 64


class Phase8ScanTailControlTests(unittest.TestCase):
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
            "scanner_resume_control": {"contract_sha256": "2" * 64},
        }
        budgets = RunBudgets.reconcile().to_dict()
        budgets["max_wall_seconds"] = 168 * 60 * 60
        self.state.create_run(
            RUN_ID,
            mode="reconcile",
            plan={"execution_contract": self.contract},
            budgets=budgets,
            fingerprints=self.fingerprints,
            status="running",
        )
        self.rows = []
        statuses = ("complete", "failed", "pending", "running")
        for index, status in enumerate(statuses):
            repository_id = "R_public_%d" % index
            full_name = "public/example-%d" % index
            head_sha = ("%x" % (index + 10)) * 40
            self.state.upsert_repository({
                "node_id": repository_id,
                "full_name": full_name,
                "visibility": "public",
                "head_sha": head_sha,
            })
            task_id = self.state.enqueue_task(
                RUN_ID,
                "scan",
                ("%x" % (index + 1)) * 64,
                repository_id=repository_id,
                payload={
                    "full_name": full_name,
                    "head_sha": head_sha,
                    "libraries": ["cublas"],
                },
                max_attempts=2,
            )
            self.rows.append((task_id, full_name, head_sha, repository_id))
            if status == "complete":
                self.state.connection.execute(
                    """
                    UPDATE tasks SET status='complete',attempts=1,
                        result_json='{}',finished_at=updated_at
                    WHERE task_id=?
                    """,
                    (task_id,),
                )
            elif status == "failed":
                self.state.connection.execute(
                    """
                    UPDATE tasks SET status='failed',attempts=2,
                        error_code='invalid_notebook',finished_at=updated_at
                    WHERE task_id=?
                    """,
                    (task_id,),
                )
            elif status == "pending":
                self.state.connection.execute(
                    """
                    UPDATE tasks SET status='pending',attempts=1,
                        error_code='repository_timeout'
                    WHERE task_id=?
                    """,
                    (task_id,),
                )
            else:
                self.state.connection.execute(
                    """
                    UPDATE tasks SET status='running',attempts=2,
                        error_code='repository_timeout',
                        lease_owner='dead-coordinator',lease_expires_at=0
                    WHERE task_id=?
                    """,
                    (task_id,),
                )
                for attempt in (1, 2):
                    self.state.connection.execute(
                        """
                        INSERT INTO scan_attempts(
                            task_id,attempt,run_id,repository_id,task_key,
                            payload_sha256,head_sha,status,retryable,error_code,
                            seconds,current_tree_triage_seconds,
                            history_dating_seconds,analysis_seconds,
                            git_subprocess_count,network_clone_count,
                            network_fetch_count,network_materialized_bytes,
                            usage_complete,started_at,finished_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            str(task_id),
                            attempt,
                            RUN_ID,
                            repository_id,
                            ("%x" % (index + 1)) * 64,
                            "3" * 64,
                            head_sha,
                            "failed" if attempt == 1 else "running",
                            1,
                            "repository_timeout",
                            1.0 if attempt == 1 else None,
                            1.0 if attempt == 1 else None,
                            0.0 if attempt == 1 else None,
                            0.0 if attempt == 1 else None,
                            1 if attempt == 1 else None,
                            0 if attempt == 1 else None,
                            0 if attempt == 1 else None,
                            0 if attempt == 1 else None,
                            1 if attempt == 1 else 0,
                            "2026-08-02T00:00:00Z",
                            "2026-08-02T00:00:01Z" if attempt == 1 else None,
                        ),
                    )
        self.state.connection.commit()

    def tearDown(self):
        self.state.close()
        self.temporary.cleanup()

    def _audit(self):
        return {
            "version": 1,
            "predecessor_source_commit": _PREDECESSOR_COMMIT,
            "successor_source_commit": "e" * 40,
            "changed_paths": sorted(_CHANGED_PATHS),
            "prior_network_task_source_sha256": PRIOR_NETWORK,
            "current_network_task_source_sha256": "4" * 64,
            "source_audit_sha256": "5" * 64,
        }

    def test_control_closes_and_quarantines_exact_unresolved_set(self):
        with (
            mock.patch(
                "collector.phase8_tail_control.PHASE8_SCAN_TASK_UNIVERSE", 4
            ),
            mock.patch(
                "collector.phase8_tail_control._source_audit",
                return_value=self._audit(),
            ),
            mock.patch(
                "collector.phase8_tail_control."
                "_validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            report = authorize_phase8_scan_tail_deferral(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
                reason="phase8_owner_deferred_scan_retry_tail",
            )
        self.assertEqual(3, report["deferred_repository_count"])
        self.assertEqual(1, report["interrupted_attempts_closed"])
        self.assertEqual(0, report["new_scan_attempts"])
        counts = dict(self.state.connection.execute(
            "SELECT status,COUNT(*) FROM tasks GROUP BY status"
        ).fetchall())
        self.assertEqual({"complete": 1, "failed": 3}, counts)
        interrupted = self.state.connection.execute(
            "SELECT status,usage_complete FROM scan_attempts WHERE attempt=2"
        ).fetchone()
        self.assertEqual(("interrupted", 0), tuple(interrupted))
        self.assertTrue(Path(report["note_path"]).exists())
        self.state.assert_run_publishable(RUN_ID)

        plan = json.loads(self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()[0])
        deferral = plan["execution_contract"]["scan_tail_deferral"]
        publishable = {}
        grouped = {}
        for index, (
            _task_id,
            full_name,
            head_sha,
            repository_id,
        ) in enumerate(self.rows[1:]):
            if index != 0:
                grouped[full_name] = (
                    {"cublas", "cuda"} if index == 1 else {"cublas"}
                )
            if index == 0:
                continue
            publishable[full_name] = RepositoryMetadata(
                request_key=full_name,
                requested_node_id=repository_id,
                requested_full_name=full_name,
                node_id=repository_id,
                full_name=full_name,
                visibility="PUBLIC",
                is_private=False,
                is_fork=False,
                is_archived=False,
                default_branch="main",
                head_oid=head_sha,
                renamed=False,
                status="ok",
            )
        with mock.patch(
            "collector.pipeline.PHASE8_SCAN_TASK_UNIVERSE", 4
        ):
            filtered, metrics = _apply_phase8_scan_tail_deferral(
                self.state,
                RUN_ID,
                grouped,
                publishable,
                {"scan_tail_deferral": deferral},
            )
        self.assertEqual({}, filtered)
        self.assertEqual(3, metrics["deferred_repositories"])

        changed = dict(publishable)
        full_name = self.rows[2][1]
        changed[full_name] = RepositoryMetadata(
            **{
                **changed[full_name].__dict__,
                "node_id": "R_changed",
            }
        )
        with (
            mock.patch("collector.pipeline.PHASE8_SCAN_TASK_UNIVERSE", 4),
            self.assertRaisesRegex(
                PipelineError, "deferred repository identity changed"
            ),
        ):
            _apply_phase8_scan_tail_deferral(
                self.state,
                RUN_ID,
                grouped,
                changed,
                {"scan_tail_deferral": deferral},
            )

    def test_resume_control_preserves_every_durable_scan_row(self):
        def resume_audit():
            return {
                "version": 1,
                "predecessor_source_commit": _RESUME_PREDECESSOR_COMMIT,
                "successor_source_commit": "f" * 40,
                "changed_paths": sorted(_RESUME_CHANGED_PATHS),
                "prior_network_task_source_sha256": "4" * 64,
                "current_network_task_source_sha256": "6" * 64,
                "source_audit_sha256": "7" * 64,
            }

        with (
            mock.patch(
                "collector.phase8_tail_control.PHASE8_SCAN_TASK_UNIVERSE", 4
            ),
            mock.patch(
                "collector.phase8_tail_control._source_audit",
                return_value=self._audit(),
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_scan_tail_deferral(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
                reason="phase8_owner_deferred_scan_retry_tail",
            )

        # Reproduce the generic resume disposition that ran once before this
        # incident was understood. The supplemental control may restore only
        # an exact member of the certified deferred set.
        self.state.connection.execute(
            """
            UPDATE tasks SET status='pending',finished_at=NULL
            WHERE task_id=?
            """,
            (self.rows[2][0],),
        )
        self.state.connection.commit()
        before = {
            "tasks": list(self.state.connection.execute(
                """
                SELECT task_id,run_id,stage,task_key,repository_id,library_id,
                       payload_json,result_json,attempts,max_attempts,created_at
                FROM tasks ORDER BY task_id
                """
            )),
            "attempts": list(self.state.connection.execute(
                "SELECT * FROM scan_attempts ORDER BY task_id,attempt"
            )),
            "results": list(self.state.connection.execute(
                "SELECT * FROM scan_results ORDER BY scan_result_id"
            )),
        }
        with (
            mock.patch(
                "collector.phase8_tail_control._resume_source_audit",
                return_value=resume_audit(),
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            report = authorize_phase8_scan_tail_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
            )
        self.assertEqual(0, report["new_scan_attempts"])
        self.assertEqual(0, report["changed_scan_results"])
        self.assertEqual(1, report["reterminalized_scan_tasks"])
        self.assertEqual(
            before["tasks"],
            list(self.state.connection.execute(
                """
                SELECT task_id,run_id,stage,task_key,repository_id,library_id,
                       payload_json,result_json,attempts,max_attempts,created_at
                FROM tasks ORDER BY task_id
                """
            )),
        )
        self.assertEqual(
            before["attempts"],
            list(self.state.connection.execute(
                "SELECT * FROM scan_attempts ORDER BY task_id,attempt"
            )),
        )
        self.assertEqual(
            before["results"],
            list(self.state.connection.execute(
                "SELECT * FROM scan_results ORDER BY scan_result_id"
            )),
        )
        plan = json.loads(self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()[0])
        contract = plan["execution_contract"]
        self.assertEqual(
            "6" * 64, contract["network_task_source_sha256"]
        )
        self.assertEqual(
            "phase8-scan-tail-resume-control",
            contract["scan_tail_resume_control"]["kind"],
        )
        run = self.state.connection.execute(
            "SELECT budgets_json,base_release_id FROM runs WHERE run_id=?",
            (RUN_ID,),
        ).fetchone()
        resumed = self.state.resume_compatible_run(
            mode="reconcile",
            budgets=json.loads(run["budgets_json"]),
            fingerprints=self.fingerprints,
            base_release_id=run["base_release_id"],
            execution_contract=contract,
        )
        self.assertEqual(RUN_ID, resumed)
        counts = dict(self.state.connection.execute(
            "SELECT status,COUNT(*) FROM tasks GROUP BY status"
        ).fetchall())
        self.assertEqual({"complete": 1, "failed": 3}, counts)

    def test_privacy_control_narrows_generic_resume_partition(self):
        with (
            mock.patch(
                "collector.phase8_tail_control.PHASE8_SCAN_TASK_UNIVERSE", 4
            ),
            mock.patch(
                "collector.phase8_tail_control._source_audit",
                return_value=self._audit(),
            ),
            mock.patch(
                "collector.phase8_tail_control."
                "_validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_scan_tail_deferral(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
                reason="phase8_owner_deferred_scan_retry_tail",
            )

        # Fresh metadata purges one formerly deferred repository through the
        # repository/task foreign key.  The privacy certificate binds the two
        # surviving deferred task keys as the effective recovery partition.
        self.state.connection.execute(
            "DELETE FROM repositories WHERE node_id=?", (self.rows[1][3],)
        )
        remaining = [
            str(row[0])
            for row in self.state.connection.execute(
                """
                SELECT task_key FROM tasks
                WHERE run_id=? AND stage='scan' AND status='failed'
                ORDER BY task_key
                """,
                (RUN_ID,),
            )
        ]
        plan = json.loads(self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()[0])
        privacy = {
            "version": 1,
            "kind": "phase8-privacy-resume-control",
            "policy": "purge-nonpublic-and-pin-surviving-scan-evidence",
            "prior_scan_task_count": 4,
            "current_scan_task_count": 3,
            "current_completed_scan_task_count": 1,
            "current_deferred_scan_task_count": 2,
            "purged_scan_task_count": 1,
            "purged_completed_scan_task_count": 0,
            "purged_deferred_scan_task_count": 1,
            "remaining_deferred_task_keys": remaining,
            "remaining_deferred_task_keys_sha256": hashlib.sha256(
                canonical_json(remaining).encode()
            ).hexdigest(),
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        privacy["contract_sha256"] = hashlib.sha256(
            canonical_json(privacy).encode()
        ).hexdigest()
        contract = plan["execution_contract"]
        contract["privacy_resume_control"] = privacy
        self.state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=?",
            (canonical_json(plan), RUN_ID),
        )
        self.state.connection.commit()
        self.state.update_stage(
            RUN_ID,
            "phase8_privacy_resume_control",
            status="complete",
            checkpoint={"control": privacy},
        )
        self.state.assert_run_publishable(RUN_ID)
        run = self.state.connection.execute(
            "SELECT budgets_json,base_release_id FROM runs WHERE run_id=?",
            (RUN_ID,),
        ).fetchone()
        resumed = self.state.resume_compatible_run(
            mode="reconcile",
            budgets=json.loads(run["budgets_json"]),
            fingerprints=self.fingerprints,
            base_release_id=run["base_release_id"],
            execution_contract=contract,
        )
        self.assertEqual(RUN_ID, resumed)
        self.assertEqual(
            {"complete": 1, "failed": 2},
            dict(self.state.connection.execute(
                "SELECT status,COUNT(*) FROM tasks GROUP BY status"
            ).fetchall()),
        )

        # A later authoritative metadata epoch proves the one surviving
        # completed repository is now missing.  The chained privacy control
        # narrows only the completed side of the same deferred partition.
        self.state.connection.execute(
            "DELETE FROM repositories WHERE node_id=?", (self.rows[0][3],)
        )
        post_refresh = {
            "version": 2,
            "kind": "phase8-post-refresh-privacy-control",
            "policy": (
                "adopt-one-additional-nonpublic-purge-and-pin-surviving-evidence"
            ),
            "privacy_resume_contract_sha256": privacy["contract_sha256"],
            "prior_scan_task_count": 3,
            "current_scan_task_count": 2,
            "prior_completed_scan_task_count": 1,
            "current_completed_scan_task_count": 0,
            "current_deferred_scan_task_count": 2,
            "additional_purged_scan_task_count": 1,
            "additional_purged_completed_scan_task_count": 1,
            "additional_purged_deferred_scan_task_count": 0,
            "remaining_deferred_task_keys": remaining,
            "remaining_deferred_task_keys_sha256": hashlib.sha256(
                canonical_json(remaining).encode()
            ).hexdigest(),
            "deferred_scan_head_pin_count": 0,
            "deferred_scan_head_pins": [],
            "deferred_scan_head_pins_sha256": hashlib.sha256(
                canonical_json([]).encode()
            ).hexdigest(),
            "new_scan_attempts": 0,
            "changed_surviving_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        post_refresh["contract_sha256"] = hashlib.sha256(
            canonical_json(post_refresh).encode()
        ).hexdigest()
        contract["post_refresh_privacy_control"] = post_refresh
        self.state.connection.execute(
            "UPDATE runs SET plan_json=?,status='failed' WHERE run_id=?",
            (canonical_json(plan), RUN_ID),
        )
        self.state.connection.commit()
        self.state.update_stage(
            RUN_ID,
            "phase8_post_refresh_privacy_control",
            status="complete",
            checkpoint={"control": post_refresh},
        )
        resumed = self.state.resume_compatible_run(
            mode="reconcile",
            budgets=json.loads(run["budgets_json"]),
            fingerprints=self.fingerprints,
            base_release_id=run["base_release_id"],
            execution_contract=contract,
        )
        self.assertEqual(RUN_ID, resumed)
        self.assertEqual(
            {"failed": 2},
            dict(self.state.connection.execute(
                "SELECT status,COUNT(*) FROM tasks GROUP BY status"
            ).fetchall()),
        )

        privacy_stage = self.state.connection.execute(
            """
            SELECT checkpoint_json FROM stages
            WHERE run_id=? AND stage='phase8_privacy_resume_control'
            """,
            (RUN_ID,),
        ).fetchone()
        tampered = json.loads(privacy_stage[0])
        tampered["control"]["remaining_deferred_task_keys"] = remaining[:1]
        self.state.connection.execute(
            "UPDATE stages SET checkpoint_json=? WHERE run_id=? AND stage=?",
            (
                canonical_json(tampered), RUN_ID,
                "phase8_privacy_resume_control",
            ),
        )
        self.state.connection.execute(
            "UPDATE runs SET status='failed' WHERE run_id=?", (RUN_ID,)
        )
        self.state.connection.commit()
        with self.assertRaisesRegex(
            RuntimeError, "owner-deferred privacy certificate is invalid"
        ):
            self.state.resume_compatible_run(
                mode="reconcile",
                budgets=json.loads(run["budgets_json"]),
                fingerprints=self.fingerprints,
                base_release_id=run["base_release_id"],
                execution_contract=contract,
            )

    def test_downstream_control_preserves_scans_and_citation_cache(self):
        resume_audit = {
            "version": 1,
            "predecessor_source_commit": _RESUME_PREDECESSOR_COMMIT,
            "successor_source_commit": "f" * 40,
            "changed_paths": sorted(_RESUME_CHANGED_PATHS),
            "prior_network_task_source_sha256": "4" * 64,
            "current_network_task_source_sha256": "6" * 64,
            "source_audit_sha256": "7" * 64,
        }
        downstream_audit = {
            "version": 1,
            "predecessor_source_commit": _DOWNSTREAM_PREDECESSOR_COMMIT,
            "successor_source_commit": "a" * 40,
            "changed_paths": sorted(_DOWNSTREAM_CHANGED_PATHS),
            "prior_network_task_source_sha256": "6" * 64,
            "current_network_task_source_sha256": "8" * 64,
            "source_audit_sha256": "9" * 64,
        }
        with (
            mock.patch(
                "collector.phase8_tail_control.PHASE8_SCAN_TASK_UNIVERSE", 4
            ),
            mock.patch(
                "collector.phase8_tail_control._source_audit",
                return_value=self._audit(),
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_scan_tail_deferral(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
                reason="phase8_owner_deferred_scan_retry_tail",
            )
        with (
            mock.patch(
                "collector.phase8_tail_control._resume_source_audit",
                return_value=resume_audit,
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_scan_tail_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
            )
        for stage, status in (
            ("scan", "complete"),
            ("aggregation", "complete"),
            ("citations", "complete"),
            ("publication", "failed"),
        ):
            self.state.update_stage(RUN_ID, stage, status=status)
        before = {
            "tasks": list(self.state.connection.execute(
                "SELECT * FROM tasks ORDER BY task_id"
            )),
            "attempts": list(self.state.connection.execute(
                "SELECT * FROM scan_attempts ORDER BY task_id,attempt"
            )),
            "results": list(self.state.connection.execute(
                "SELECT * FROM scan_results ORDER BY scan_result_id"
            )),
            "citations": list(self.state.connection.execute(
                """
                SELECT * FROM citation_cache
                ORDER BY library_id,query_fp,work_id
                """
            )),
        }
        with (
            mock.patch(
                "collector.phase8_tail_control._downstream_source_audit",
                return_value=downstream_audit,
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            report = authorize_phase8_downstream_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
            )
        self.assertEqual(0, report["new_scan_attempts"])
        self.assertEqual(0, report["changed_scan_results"])
        self.assertEqual(0, report["changed_citation_cache_entries"])
        self.assertEqual(
            before["tasks"],
            list(self.state.connection.execute(
                "SELECT * FROM tasks ORDER BY task_id"
            )),
        )
        self.assertEqual(
            before["attempts"],
            list(self.state.connection.execute(
                "SELECT * FROM scan_attempts ORDER BY task_id,attempt"
            )),
        )
        self.assertEqual(
            before["results"],
            list(self.state.connection.execute(
                "SELECT * FROM scan_results ORDER BY scan_result_id"
            )),
        )
        self.assertEqual(
            before["citations"],
            list(self.state.connection.execute(
                """
                SELECT * FROM citation_cache
                ORDER BY library_id,query_fp,work_id
                """
            )),
        )
        plan = json.loads(self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()[0])
        contract = plan["execution_contract"]
        self.assertEqual("8" * 64, contract["network_task_source_sha256"])
        self.assertEqual(
            "phase8-downstream-resume-control",
            contract["downstream_resume_control"]["kind"],
        )
        self.assertEqual(
            contract["downstream_resume_control"],
            _validate_phase8_downstream_resume_control(
                contract["downstream_resume_control"],
                contract["scan_tail_resume_control"],
            ),
        )
        tampered = dict(contract["downstream_resume_control"])
        tampered["changed_citation_cache_entries"] = 1
        with self.assertRaisesRegex(
            PipelineError, "downstream resume control is invalid"
        ):
            _validate_phase8_downstream_resume_control(
                tampered,
                contract["scan_tail_resume_control"],
            )

    def test_downstream_control_repairs_only_exact_generic_supersession(self):
        resume_audit = {
            "version": 1,
            "predecessor_source_commit": _RESUME_PREDECESSOR_COMMIT,
            "successor_source_commit": "f" * 40,
            "changed_paths": sorted(_RESUME_CHANGED_PATHS),
            "prior_network_task_source_sha256": "4" * 64,
            "current_network_task_source_sha256": "6" * 64,
            "source_audit_sha256": "7" * 64,
        }
        downstream_audit = {
            "version": 1,
            "predecessor_source_commit": _DOWNSTREAM_PREDECESSOR_COMMIT,
            "successor_source_commit": "a" * 40,
            "changed_paths": sorted(_DOWNSTREAM_CHANGED_PATHS),
            "prior_network_task_source_sha256": "6" * 64,
            "current_network_task_source_sha256": "8" * 64,
            "source_audit_sha256": "9" * 64,
        }
        with (
            mock.patch(
                "collector.phase8_tail_control.PHASE8_SCAN_TASK_UNIVERSE", 4
            ),
            mock.patch(
                "collector.phase8_tail_control._source_audit",
                return_value=self._audit(),
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_scan_tail_deferral(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
                reason="phase8_owner_deferred_scan_retry_tail",
            )
        with (
            mock.patch(
                "collector.phase8_tail_control._resume_source_audit",
                return_value=resume_audit,
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_scan_tail_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
            )
        baseline = {
            row["task_id"]: row["result_json"]
            for row in self.state.connection.execute(
                "SELECT task_id,result_json FROM tasks WHERE status='failed'"
            )
        }
        repair_path = self.root / "pre-supersession.sqlite3"
        reference = sqlite3.connect(repair_path)
        try:
            self.state.connection.backup(reference)
        finally:
            reference.close()
        superseded = json.dumps(
            {"reason": "replanned_immutable_work", "superseded": True},
            sort_keys=True,
            separators=(",", ":"),
        )
        self.state.connection.execute(
            """
            UPDATE tasks SET status='complete',result_json=?,
                finished_at=updated_at
            WHERE run_id=? AND stage='scan' AND status='failed'
            """,
            (superseded, RUN_ID),
        )
        self.state.connection.execute(
            "UPDATE runs SET status='failed' WHERE run_id=?", (RUN_ID,)
        )
        for stage, status in (
            ("scan", "complete"),
            ("aggregation", "complete"),
            ("citations", "complete"),
            ("publication", "failed"),
        ):
            self.state.update_stage(RUN_ID, stage, status=status)
        with (
            mock.patch(
                "collector.phase8_tail_control._downstream_source_audit",
                return_value=downstream_audit,
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            report = authorize_phase8_downstream_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
                repair_state_path=repair_path,
            )
        self.assertEqual(3, report["repaired_deferred_scan_tasks"])
        repaired = {
            row["task_id"]: row["result_json"]
            for row in self.state.connection.execute(
                "SELECT task_id,result_json FROM tasks WHERE status='failed'"
            )
        }
        self.assertEqual(baseline, repaired)
        counts = dict(self.state.connection.execute(
            "SELECT status,COUNT(*) FROM tasks GROUP BY status"
        ).fetchall())
        self.assertEqual({"complete": 1, "failed": 3}, counts)

    def test_visibility_control_preserves_state_and_hashes_missing_node(self):
        resume_audit = {
            "version": 1,
            "predecessor_source_commit": _RESUME_PREDECESSOR_COMMIT,
            "successor_source_commit": "f" * 40,
            "changed_paths": sorted(_RESUME_CHANGED_PATHS),
            "prior_network_task_source_sha256": "4" * 64,
            "current_network_task_source_sha256": "6" * 64,
            "source_audit_sha256": "7" * 64,
        }
        downstream_audit = {
            "version": 1,
            "predecessor_source_commit": _DOWNSTREAM_PREDECESSOR_COMMIT,
            "successor_source_commit": "a" * 40,
            "changed_paths": sorted(_DOWNSTREAM_CHANGED_PATHS),
            "prior_network_task_source_sha256": "6" * 64,
            "current_network_task_source_sha256": "8" * 64,
            "source_audit_sha256": "9" * 64,
        }
        visibility_audit = {
            "version": 1,
            "predecessor_source_commit": _VISIBILITY_PREDECESSOR_COMMIT,
            "successor_source_commit": "b" * 40,
            "changed_paths": sorted(_VISIBILITY_CHANGED_PATHS),
            "prior_network_task_source_sha256": "8" * 64,
            "current_network_task_source_sha256": "a" * 64,
            "source_audit_sha256": "b" * 64,
        }
        with (
            mock.patch(
                "collector.phase8_tail_control.PHASE8_SCAN_TASK_UNIVERSE", 4
            ),
            mock.patch(
                "collector.phase8_tail_control._source_audit",
                return_value=self._audit(),
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_scan_tail_deferral(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
                reason="phase8_owner_deferred_scan_retry_tail",
            )
        with (
            mock.patch(
                "collector.phase8_tail_control._resume_source_audit",
                return_value=resume_audit,
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_scan_tail_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
            )
        for stage, status in (
            ("scan", "complete"),
            ("aggregation", "complete"),
            ("citations", "complete"),
            ("publication", "failed"),
        ):
            self.state.update_stage(RUN_ID, stage, status=status)
        with (
            mock.patch(
                "collector.phase8_tail_control._downstream_source_audit",
                return_value=downstream_audit,
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            authorize_phase8_downstream_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
            )

        epoch = "c" * 32
        missing_node = "R_private-proof-must-not-be-stored"
        complete_id = self.state.enqueue_task(
            RUN_ID,
            "github-final-visibility-batch",
            "epoch:%s:batch:000000:proof" % epoch[:16],
            payload={"epoch": epoch},
        )
        result = {
            "repositories": [{
                "request_key": "node:" + missing_node,
                "requested_node_id": missing_node,
                "requested_full_name": None,
                "node_id": None,
                "full_name": None,
                "admitted_public": False,
                "status": "missing",
                "is_fork": None,
                "is_archived": None,
                "error_count": 0,
            }],
        }
        self.state.connection.execute(
            """
            UPDATE tasks SET status='complete',result_json=?,
                finished_at=updated_at WHERE task_id=?
            """,
            (json.dumps(result, sort_keys=True), complete_id),
        )
        self.state.enqueue_task(
            RUN_ID,
            "github-final-visibility-batch",
            "epoch:%s:batch:000001:proof" % epoch[:16],
            payload={"epoch": epoch},
        )
        self.state.update_stage(RUN_ID, "final_visibility", status="failed")
        self.state.update_stage(RUN_ID, "publication", status="failed")
        self.state.connection.execute(
            "UPDATE runs SET status='failed' WHERE run_id=?", (RUN_ID,)
        )
        self.state.connection.commit()
        before = {
            "tasks": list(self.state.connection.execute(
                "SELECT * FROM tasks ORDER BY task_id"
            )),
            "attempts": list(self.state.connection.execute(
                "SELECT * FROM scan_attempts ORDER BY task_id,attempt"
            )),
            "results": list(self.state.connection.execute(
                "SELECT * FROM scan_results ORDER BY scan_result_id"
            )),
            "citations": list(self.state.connection.execute(
                "SELECT * FROM citation_cache ORDER BY library_id,query_fp,work_id"
            )),
        }
        with (
            mock.patch(
                "collector.phase8_tail_control._visibility_source_audit",
                return_value=visibility_audit,
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda contract, **_kwargs: contract,
            ),
        ):
            report = authorize_phase8_visibility_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
            )
        self.assertEqual(1, report["missing_repositories"])
        self.assertEqual(0, report["new_scan_attempts"])
        for key, query in (
            ("tasks", "SELECT * FROM tasks ORDER BY task_id"),
            (
                "attempts",
                "SELECT * FROM scan_attempts ORDER BY task_id,attempt",
            ),
            (
                "results",
                "SELECT * FROM scan_results ORDER BY scan_result_id",
            ),
            (
                "citations",
                "SELECT * FROM citation_cache ORDER BY library_id,query_fp,work_id",
            ),
        ):
            self.assertEqual(
                before[key], list(self.state.connection.execute(query))
            )
        plan = json.loads(self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()[0])
        contract = plan["execution_contract"]
        control = contract["visibility_resume_control"]
        self.assertNotIn(missing_node, json.dumps(control))
        self.assertEqual(
            hashlib.sha256(missing_node.encode()).hexdigest(),
            control["missing_repository_node_sha256"],
        )
        self.assertEqual(
            control,
            _validate_phase8_visibility_resume_control(
                control, contract["downstream_resume_control"]
            ),
        )
        tampered = dict(control)
        tampered["pending_visibility_batch_count"] = 0
        with self.assertRaisesRegex(
            PipelineError, "visibility resume control is invalid"
        ):
            _validate_phase8_visibility_resume_control(
                tampered, contract["downstream_resume_control"]
            )

        metadata_document = {
            "version": 2,
            "kind": "github-metadata-batch",
            "repositories": [],
            "errors": [],
            "request_count": 1,
            "points_used": 1,
            "remaining": 4999,
            "reset_at": "2026-08-03T00:00:00Z",
        }
        base_key = "batch:000000:embedded"
        base_id = self.state.enqueue_task(
            RUN_ID,
            "github-metadata-batch",
            base_key,
            payload={"version": 1, "lookups": []},
        )
        self.state.connection.execute(
            "UPDATE tasks SET status='complete',result_json=? WHERE task_id=?",
            (json.dumps(metadata_document, sort_keys=True), base_id),
        )
        fresh_epoch = "d" * 16
        fresh_complete = self.state.enqueue_task(
            RUN_ID,
            "github-metadata-batch",
            "fresh:%s:batch:000000:complete" % fresh_epoch,
            payload={"version": 1, "lookups": []},
        )
        self.state.connection.execute(
            "UPDATE tasks SET status='complete',result_json=? WHERE task_id=?",
            (json.dumps(metadata_document, sort_keys=True), fresh_complete),
        )
        fresh_pending = self.state.enqueue_task(
            RUN_ID,
            "github-metadata-batch",
            "fresh:%s:batch:000001:pending" % fresh_epoch,
            payload={"version": 1, "lookups": []},
        )
        self.state.connection.execute(
            """
            UPDATE tasks SET attempts=1,
                error_code='github-metadata-batch-failed'
            WHERE task_id=?
            """,
            (fresh_pending,),
        )
        base_result = self.state.connection.execute(
            "SELECT result_json FROM tasks WHERE task_id=?", (base_id,)
        ).fetchone()[0]
        result_universe = [{
            "task_key": base_key,
            "result_sha256": hashlib.sha256(
                base_result.encode()
            ).hexdigest(),
        }]
        plan = json.loads(self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()[0])
        plan["execution_contract"]["preseeded_metadata_epoch"] = {
            "task_count": 1,
            "lookup_count": 0,
            "task_universe_sha256": "e" * 64,
            "result_universe_sha256": hashlib.sha256(
                canonical_json(result_universe).encode()
            ).hexdigest(),
            "input_context_sha256": "f" * 64,
        }
        plan["execution_contract"]["historical_graphql_usage"] = {
            "request_count": 1,
            "points_used": 1,
            "remaining": None,
            "reset_at": None,
        }
        self.state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=?",
            (canonical_json(plan), RUN_ID),
        )
        self.state.update_stage(RUN_ID, "metadata", status="failed")
        self.state.connection.commit()
        graphql_audit = {
            "version": 1,
            "predecessor_source_commit": _GRAPHQL_PREDECESSOR_COMMIT,
            "successor_source_commit": "c" * 40,
            "changed_paths": sorted(_GRAPHQL_CHANGED_PATHS),
            "prior_network_task_source_sha256": "a" * 64,
            "current_network_task_source_sha256": "c" * 64,
            "source_audit_sha256": "d" * 64,
        }
        before_graphql_tasks = list(self.state.connection.execute(
            "SELECT * FROM tasks ORDER BY task_id"
        ))
        with (
            mock.patch(
                "collector.phase8_tail_control._graphql_source_audit",
                return_value=graphql_audit,
            ),
            mock.patch(
                "collector.phase8_tail_control._validate_reviewed_execution_contract",
                side_effect=lambda reviewed, **_kwargs: reviewed,
            ),
        ):
            graphql_report = authorize_phase8_graphql_resume_control(
                state=self.state,
                repo_root=self.root,
                run_id=RUN_ID,
            )
        self.assertEqual(1, graphql_report["embedded_points_deduplicated"])
        self.assertEqual(
            1,
            graphql_report["control"][
                "retry_pending_fresh_metadata_batch_count"
            ],
        )
        self.assertEqual(
            before_graphql_tasks,
            list(self.state.connection.execute(
                "SELECT * FROM tasks ORDER BY task_id"
            )),
        )
        plan = json.loads(self.state.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (RUN_ID,)
        ).fetchone()[0])
        graphql_control = plan["execution_contract"][
            "graphql_resume_control"
        ]
        self.assertEqual(
            graphql_control,
            _validate_phase8_graphql_resume_control(
                graphql_control,
                plan["execution_contract"]["visibility_resume_control"],
            ),
        )

    def test_v1_v2_parity_is_a_staging_gate(self):
        def fake_build(_current, _timeseries, _citations, _deltas, root, **_kw):
            (root / "manifest.json").write_text("{}", encoding="utf-8")
            return {}

        with (
            mock.patch("collector.publish_v2.build_v2_tree", side_effect=fake_build),
            mock.patch("collector.validate_v2.validate_v2", return_value=[]),
            mock.patch(
                "collector.validate_v2.compare_v1_v2",
                return_value=["semantic mismatch"],
            ),
        ):
            with self.assertRaisesRegex(
                PublicationError, "V1/V2 staging reconciliation failed"
            ):
                stage_v2({}, {}, {}, {}, self.root / "v2")

    def test_privacy_resume_validator_binds_exact_partition(self):
        graphql = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
        }
        remaining = ["3" * 64]
        control = {
            "version": 1,
            "kind": "phase8-privacy-resume-control",
            "policy": "purge-nonpublic-and-pin-surviving-scan-evidence",
            "predecessor_source_commit": (
                "4ebb8d6db10171aa3e06117f8e62dce94ac01d38"
            ),
            "successor_source_commit": "4" * 40,
            "changed_paths": [
                "collector/cli.py",
                "collector/phase8_tail_control.py",
                "collector/pipeline.py",
                "docs/Documentation.md",
                "docs/PROJECT-CONTEXT.md",
                "test_req14_phase8_tail_control.py",
                "test_req14_pipeline.py",
            ],
            "source_audit_sha256": "5" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "6" * 64,
            "graphql_resume_contract_sha256": "1" * 64,
            "prior_scan_task_count": 3,
            "current_scan_task_count": 2,
            "current_completed_scan_task_count": 1,
            "current_deferred_scan_task_count": 1,
            "purged_scan_task_count": 1,
            "purged_completed_scan_task_count": 1,
            "purged_deferred_scan_task_count": 0,
            "purged_task_keys_sha256": "7" * 64,
            "purged_repository_nodes_sha256": "8" * 64,
            "remaining_deferred_task_keys": remaining,
            "remaining_deferred_task_keys_sha256": hashlib.sha256(
                canonical_json(remaining).encode()
            ).hexdigest(),
            "remaining_deferred_repository_proof_sha256": "9" * 64,
            "scan_head_pin_count": 1,
            "scan_bound_rename_count": 0,
            "fresh_metadata_epoch": "a" * 16,
            "fresh_metadata_batch_count": 2,
            "preserved_state_sha256": "b" * 64,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_privacy_resume_control(control, graphql),
        )
        invalid = dict(control)
        invalid["purged_scan_task_count"] = 2
        with self.assertRaisesRegex(
            PipelineError, "privacy resume control is invalid"
        ):
            _validate_phase8_privacy_resume_control(invalid, graphql)

    def test_fresh_candidate_deferral_validator_binds_exact_tasks(self):
        privacy = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
            "current_scan_task_count": 10,
            "current_completed_scan_task_count": 8,
            "current_deferred_scan_task_count": 2,
        }
        proof = [{
            "task_key": "3" * 64,
            "repository_identity_sha256": "4" * 64,
            "libraries": ["cublas"],
        }]
        control = {
            "version": 1,
            "kind": "phase8-fresh-candidate-deferral-control",
            "policy": "owner-defer-unscanned-post-refresh-candidates",
            "predecessor_source_commit": (
                "c97fe1a2f6d8e1f3c1d413707c41ee5da7187e51"
            ),
            "successor_source_commit": "5" * 40,
            "changed_paths": [
                "collector/cli.py",
                "collector/phase8_tail_control.py",
                "collector/pipeline.py",
                "test_req14_phase8_tail_control.py",
                "test_req14_pipeline.py",
            ],
            "source_audit_sha256": "6" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "7" * 64,
            "privacy_resume_contract_sha256": "1" * 64,
            "scan_task_universe_count": 10,
            "completed_scan_task_count": 8,
            "owner_deferred_scan_task_count": 2,
            "deferred_repository_count": 1,
            "deferred_task_proof": proof,
            "deferred_task_proof_sha256": hashlib.sha256(
                canonical_json(proof).encode()
            ).hexdigest(),
            "preserved_state_sha256": "8" * 64,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_fresh_candidate_deferral_control(
                control, privacy
            ),
        )
        invalid = json.loads(json.dumps(control))
        invalid["deferred_task_proof"][0]["libraries"] = []
        with self.assertRaisesRegex(
            PipelineError, "fresh-candidate deferral control is invalid"
        ):
            _validate_phase8_fresh_candidate_deferral_control(
                invalid, privacy
            )

    def test_visibility_set_resume_validator_binds_failed_epoch(self):
        fresh_candidate = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
        }
        control = {
            "version": 1,
            "kind": "phase8-visibility-set-resume-control",
            "policy": (
                "supersede-failed-visibility-epoch-after-fresh-metadata"
            ),
            "predecessor_source_commit": _VISIBILITY_SET_PREDECESSOR_COMMIT,
            "successor_source_commit": "3" * 40,
            "changed_paths": sorted(_VISIBILITY_SET_CHANGED_PATHS),
            "source_audit_sha256": "4" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "5" * 64,
            "fresh_candidate_deferral_contract_sha256": "1" * 64,
            "fresh_metadata_epoch": "6" * 16,
            "fresh_metadata_batch_count": 775,
            "prior_visibility_epoch": "7" * 32,
            "prior_visibility_set_sha256": "8" * 64,
            "prior_visibility_task_count": 291,
            "prior_visibility_completed_task_count": 199,
            "prior_visibility_pending_task_count": 92,
            "preserved_state_sha256": "9" * 64,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_visibility_set_resume_control(
                control, fresh_candidate
            ),
        )
        invalid = dict(control)
        invalid["prior_visibility_pending_task_count"] = 91
        with self.assertRaisesRegex(
            PipelineError, "visibility-set resume control is invalid"
        ):
            _validate_phase8_visibility_set_resume_control(
                invalid, fresh_candidate
            )

    def test_visibility_rejection_resume_validator_binds_newest_epoch(self):
        visibility_set = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
        }
        control = {
            "version": 1,
            "kind": "phase8-visibility-rejection-resume-control",
            "policy": "force-fresh-metadata-after-newest-missing-node",
            "predecessor_source_commit": (
                _VISIBILITY_REJECTION_PREDECESSOR_COMMIT
            ),
            "successor_source_commit": "3" * 40,
            "changed_paths": sorted(_VISIBILITY_REJECTION_CHANGED_PATHS),
            "source_audit_sha256": "4" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "5" * 64,
            "visibility_set_resume_contract_sha256": "1" * 64,
            "visibility_epoch": "6" * 32,
            "failed_visibility_task_key": (
                "epoch:%s:batch:000043:proof" % ("6" * 16)
            ),
            "missing_repository_node_sha256": "7" * 64,
            "visibility_batch_count": 291,
            "completed_visibility_batch_count": 44,
            "pending_visibility_batch_count": 247,
            "preserved_state_sha256": "8" * 64,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_visibility_rejection_resume_control(
                control, visibility_set
            ),
        )
        invalid = dict(control)
        invalid["completed_visibility_batch_count"] = 43
        with self.assertRaisesRegex(
            PipelineError, "visibility-rejection resume control is invalid"
        ):
            _validate_phase8_visibility_rejection_resume_control(
                invalid, visibility_set
            )

    def test_visibility_refresh_resume_validator_binds_collision(self):
        rejection = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
        }
        control = {
            "version": 1,
            "kind": "phase8-visibility-refresh-resume-control",
            "policy": "new-refresh-never-resumes-prior-partial-epoch",
            "predecessor_source_commit": (
                _VISIBILITY_REFRESH_PREDECESSOR_COMMIT
            ),
            "successor_source_commit": "3" * 40,
            "changed_paths": sorted(_VISIBILITY_REFRESH_CHANGED_PATHS),
            "source_audit_sha256": "4" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "5" * 64,
            "visibility_rejection_resume_contract_sha256": "1" * 64,
            "prior_fresh_metadata_epoch": "6" * 16,
            "prior_completed_fresh_metadata_batch_count": 775,
            "collision_pending_fresh_metadata_batch_count": 775,
            "collision_fresh_metadata_task_set_sha256": "7" * 64,
            "preserved_state_sha256": "8" * 64,
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_visibility_refresh_resume_control(
                control, rejection
            ),
        )
        invalid = dict(control)
        invalid["collision_pending_fresh_metadata_batch_count"] = 774
        with self.assertRaisesRegex(
            PipelineError, "visibility-refresh resume control is invalid"
        ):
            _validate_phase8_visibility_refresh_resume_control(
                invalid, rejection
            )

    def test_visibility_budget_resume_validator_preserves_point_cap(self):
        refresh = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
        }
        control = {
            "version": 1,
            "kind": "phase8-visibility-budget-resume-control",
            "policy": (
                "cohort-only-100-lookup-batches-with-unchanged-budget"
            ),
            "predecessor_source_commit": (
                _VISIBILITY_BUDGET_PREDECESSOR_COMMIT
            ),
            "successor_source_commit": "3" * 40,
            "changed_paths": sorted(_VISIBILITY_BUDGET_CHANGED_PATHS),
            "source_audit_sha256": "4" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "5" * 64,
            "visibility_refresh_resume_contract_sha256": "1" * 64,
            "prior_metadata_batch_size": 50,
            "current_metadata_batch_size": 100,
            "metadata_lookup_count": 38721,
            "planned_metadata_batch_count": 388,
            "planned_final_visibility_batch_count": 291,
            "journaled_graphql_points": 1792,
            "remaining_graphql_point_budget": 708,
            "projected_unit_cost_graphql_points": 2471,
            "max_graphql_points": 2500,
            "preserved_state_sha256": "6" * 64,
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_visibility_budget_resume_control(
                control, refresh
            ),
        )
        invalid = dict(control)
        invalid["projected_unit_cost_graphql_points"] = 2501
        with self.assertRaisesRegex(
            PipelineError, "visibility-budget resume control is invalid"
        ):
            _validate_phase8_visibility_budget_resume_control(
                invalid, refresh
            )

    def test_visibility_transport_retry_validator_reserves_one_point(self):
        budget_control = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
            "projected_unit_cost_graphql_points": 2471,
        }
        control = {
            "version": 1,
            "kind": "phase8-visibility-transport-retry-control",
            "policy": "reserve-one-point-for-one-malformed-graphql-response",
            "predecessor_source_commit": (
                _VISIBILITY_TRANSPORT_RETRY_PREDECESSOR_COMMIT
            ),
            "successor_source_commit": "3" * 40,
            "changed_paths": sorted(
                _VISIBILITY_TRANSPORT_RETRY_CHANGED_PATHS
            ),
            "source_audit_sha256": "4" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "5" * 64,
            "visibility_budget_resume_contract_sha256": "1" * 64,
            "retry_task_id": 413930,
            "retry_task_key_sha256": "6" * 64,
            "retry_metadata_epoch": "7" * 16,
            "completed_new_metadata_batch_count": 189,
            "pending_new_metadata_batch_count": 199,
            "failed_attempt_count": 1,
            "reserved_unobserved_points": 1,
            "journaled_observed_points": 1981,
            "projected_graphql_points_with_reserve": 2472,
            "max_graphql_points": 2500,
            "preserved_state_sha256": "8" * 64,
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_visibility_transport_retry_control(
                control, budget_control
            ),
        )
        invalid = dict(control)
        invalid["reserved_unobserved_points"] = 0
        with self.assertRaisesRegex(
            PipelineError, "visibility transport retry control is invalid"
        ):
            _validate_phase8_visibility_transport_retry_control(
                invalid, budget_control
            )

    def test_visibility_epoch_recovery_validator_binds_exact_partition(self):
        transport = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
        }
        control = {
            "version": 1,
            "kind": "phase8-visibility-epoch-recovery-control",
            "policy": (
                "restore-certified-current-epoch-and-retain-replacement-evidence"
            ),
            "predecessor_source_commit": (
                _VISIBILITY_EPOCH_RECOVERY_PREDECESSOR_COMMIT
            ),
            "successor_source_commit": "3" * 40,
            "changed_paths": sorted(_VISIBILITY_EPOCH_RECOVERY_CHANGED_PATHS),
            "source_audit_sha256": "4" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "5" * 64,
            "visibility_transport_retry_contract_sha256": "1" * 64,
            "reference_state_name": "pre-retry.sqlite3",
            "resume_metadata_epoch": "6" * 16,
            "replacement_metadata_epoch": "7" * 16,
            "resume_epoch_batch_count": 388,
            "resume_epoch_completed_batch_count": 189,
            "restored_pending_batch_count": 199,
            "replacement_completed_batch_count": 10,
            "replacement_pending_batch_count": 378,
            "additional_failed_attempt_count": 1,
            "additional_reserved_unobserved_points": 1,
            "total_reserved_unobserved_points": 2,
            "journaled_points_before_reserve": 1992,
            "projected_graphql_points_with_reserves": 2483,
            "max_graphql_points": 2500,
            "restored_task_rows_sha256": "8" * 64,
            "replacement_task_rows_sha256": "9" * 64,
            "preserved_non_task_state_sha256": "a" * 64,
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_visibility_epoch_recovery_control(
                control, transport
            ),
        )
        invalid = dict(control)
        invalid["replacement_completed_batch_count"] = 11
        with self.assertRaisesRegex(
            PipelineError, "visibility epoch recovery control is invalid"
        ):
            _validate_phase8_visibility_epoch_recovery_control(
                invalid, transport
            )

    def test_post_refresh_privacy_validator_binds_exact_purge(self):
        privacy = {
            "contract_sha256": "1" * 64,
            "current_scan_task_count": 38287,
            "current_completed_scan_task_count": 37969,
        }
        epoch = {
            "contract_sha256": "2" * 64,
            "current_network_task_source_sha256": "3" * 64,
            "resume_metadata_epoch": "4" * 16,
        }
        remaining = [f"{index:064x}" for index in range(318)]
        deferred_head_pins = [
            {
                "task_key": f"{index:064x}",
                "repository_identity_sha256": f"{index + 100:064x}",
                "head_sha": f"{index:040x}",
                "libraries": ["cublas"],
            }
            for index in range(8)
        ]
        control = {
            "version": 2,
            "kind": "phase8-post-refresh-privacy-control",
            "policy": (
                "adopt-one-additional-nonpublic-purge-and-pin-surviving-evidence"
            ),
            "predecessor_source_commit": (
                _POST_REFRESH_PRIVACY_PREDECESSOR_COMMIT
            ),
            "successor_source_commit": "5" * 40,
            "changed_paths": sorted(_POST_REFRESH_PRIVACY_CHANGED_PATHS),
            "source_audit_sha256": "6" * 64,
            "prior_network_task_source_sha256": "3" * 64,
            "current_network_task_source_sha256": "7" * 64,
            "privacy_resume_contract_sha256": "1" * 64,
            "visibility_epoch_recovery_contract_sha256": "2" * 64,
            "reference_state_name": "pre-refresh.sqlite3",
            "fresh_metadata_epoch": "4" * 16,
            "fresh_metadata_batch_count": 388,
            "prior_scan_task_count": 38287,
            "current_scan_task_count": 38286,
            "prior_completed_scan_task_count": 37969,
            "current_completed_scan_task_count": 37968,
            "current_deferred_scan_task_count": 318,
            "additional_purged_scan_task_count": 1,
            "additional_purged_completed_scan_task_count": 1,
            "additional_purged_deferred_scan_task_count": 0,
            "additional_purged_repository_count": 1,
            "additional_purged_candidate_count": 3,
            "additional_purged_scan_result_count": 3,
            "additional_purged_repo_analysis_count": 2,
            "additional_purged_task_keys_sha256": "8" * 64,
            "additional_purged_repository_nodes_sha256": "9" * 64,
            "additional_purged_evidence_sha256": "a" * 64,
            "fresh_missing_metadata_proof_sha256": "b" * 64,
            "remaining_deferred_task_keys": remaining,
            "remaining_deferred_task_keys_sha256": hashlib.sha256(
                canonical_json(remaining).encode()
            ).hexdigest(),
            "remaining_deferred_repository_proof_sha256": "c" * 64,
            "deferred_scan_head_pin_count": len(deferred_head_pins),
            "deferred_scan_head_pins": deferred_head_pins,
            "deferred_scan_head_pins_sha256": hashlib.sha256(
                canonical_json(deferred_head_pins).encode()
            ).hexdigest(),
            "scan_head_pin_count": 1538,
            "scan_bound_rename_count": 16,
            "deferred_timestamp_refresh_count": 318,
            "deferred_timestamp_refresh_rows_sha256": "f" * 64,
            "remaining_scan_task_rows_sha256": "d" * 64,
            "preserved_state_sha256": "e" * 64,
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_surviving_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_post_refresh_privacy_control(
                control, privacy, epoch
            ),
        )
        invalid = dict(control)
        invalid["additional_purged_scan_result_count"] = 4
        with self.assertRaisesRegex(
            PipelineError, "post-refresh privacy control is invalid"
        ):
            _validate_phase8_post_refresh_privacy_control(
                invalid, privacy, epoch
            )

    def test_final_visibility_privacy_validator_binds_exact_purge(self):
        remaining = [f"{index:064x}" for index in range(318)]
        deferred_head_pins = [
            {
                "task_key": f"{index:064x}",
                "repository_identity_sha256": f"{index + 100:064x}",
                "head_sha": f"{index:040x}",
                "libraries": ["cublas"],
            }
            for index in range(8)
        ]
        post = {
            "contract_sha256": "1" * 64,
            "current_network_task_source_sha256": "2" * 64,
            "remaining_deferred_task_keys": remaining,
            "remaining_deferred_repository_proof_sha256": "3" * 64,
            "deferred_scan_head_pins": deferred_head_pins,
        }
        control = {
            "version": 1,
            "kind": "phase8-final-visibility-privacy-control",
            "policy": (
                "purge-one-final-missing-node-and-resume-compatible-epoch"
            ),
            "predecessor_source_commit": (
                _FINAL_VISIBILITY_PRIVACY_PREDECESSOR_COMMIT
            ),
            "successor_source_commit": "4" * 40,
            "changed_paths": sorted(
                _FINAL_VISIBILITY_PRIVACY_CHANGED_PATHS
            ),
            "source_audit_sha256": "5" * 64,
            "prior_network_task_source_sha256": "2" * 64,
            "current_network_task_source_sha256": "6" * 64,
            "post_refresh_privacy_contract_sha256": "1" * 64,
            "final_visibility_epoch": "7" * 32,
            "final_visibility_task_count": 291,
            "final_visibility_completed_task_count": 172,
            "final_visibility_pending_task_count": 119,
            "rejected_task_id": 414688,
            "rejected_task_key_sha256": "8" * 64,
            "rejected_repository_node_sha256": "9" * 64,
            "rejected_repository_identity_sha256": "a" * 64,
            "rejected_final_visibility_proof_sha256": "b" * 64,
            "prior_scan_task_count": 38286,
            "current_scan_task_count": 38285,
            "prior_completed_scan_task_count": 37968,
            "current_completed_scan_task_count": 37967,
            "current_deferred_scan_task_count": 318,
            "purged_scan_task_count": 1,
            "purged_completed_scan_task_count": 1,
            "purged_deferred_scan_task_count": 0,
            "purged_repository_count": 1,
            "purged_candidate_count": 8,
            "purged_scan_result_count": 2,
            "purged_repo_analysis_count": 2,
            "purged_scan_attempt_count": 1,
            "purged_task_key_sha256": "c" * 64,
            "purged_evidence_sha256": "d" * 64,
            "remaining_deferred_task_keys": remaining,
            "remaining_deferred_task_keys_sha256": hashlib.sha256(
                canonical_json(remaining).encode()
            ).hexdigest(),
            "remaining_deferred_repository_proof_sha256": "3" * 64,
            "deferred_scan_head_pin_count": 8,
            "deferred_scan_head_pins": deferred_head_pins,
            "deferred_scan_head_pins_sha256": hashlib.sha256(
                canonical_json(deferred_head_pins).encode()
            ).hexdigest(),
            "scan_head_pin_count": 1538,
            "scan_bound_rename_count": 16,
            "preserved_final_visibility_tasks_sha256": "e" * 64,
            "preserved_citation_cache_sha256": "f" * 64,
            "new_metadata_request_count": 0,
            "new_final_visibility_request_count": 0,
            "new_scan_attempts": 0,
            "changed_surviving_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = hashlib.sha256(
            canonical_json(control).encode()
        ).hexdigest()
        self.assertEqual(
            control,
            _validate_phase8_final_visibility_privacy_control(
                control, post
            ),
        )
        invalid = dict(control)
        invalid["purged_candidate_count"] = 7
        with self.assertRaisesRegex(
            PipelineError,
            "final-visibility privacy control is invalid",
        ):
            _validate_phase8_final_visibility_privacy_control(invalid, post)


if __name__ == "__main__":
    unittest.main()
