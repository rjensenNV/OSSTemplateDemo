"""Focused immutable historical scan-usage pipeline tests."""

from __future__ import annotations

import copy
import dataclasses
import tempfile
import types
import unittest
from pathlib import Path

from collector import config
from collector.pipeline import (
    BudgetExceeded,
    CollectorPipeline,
    PipelineError,
    RunBudgets,
    _canonical_sha256,
    _combine_scan_attempt_usage,
    _enforce_scan_attempt_budgets,
    _network_task_source_sha256,
    _scan_attempt_usage_for_run,
    _validate_historical_scan_usage,
    _validate_reviewed_execution_contract,
)
from collector.state import StateDB
from collector.successor import (
    _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY,
    _sha256,
)


HEAD_SHA = "a" * 40
CURRENT_USAGE = {
    "usage_complete": True,
    "attempt_count": 1,
    "complete_attempts": 1,
    "failed_attempts": 0,
    "interrupted_attempts": 0,
    "seconds": 5.0,
    "current_tree_triage_seconds": 1.0,
    "history_dating_seconds": 2.0,
    "analysis_seconds": 2.0,
    "git_subprocess_count": 4,
    "network_clone_count": 0,
    "network_fetch_count": 1,
    "network_materialized_bytes": 50,
}

CURRENT_USAGE_WITH_UNKNOWN = {
    **CURRENT_USAGE,
    "attempt_count": 2,
    "exact_attempt_count": 1,
    "irreconstructible_attempt_count": 1,
    "timing_known_attempt_count": 1,
    "timing_unknown_attempt_count": 1,
    "interrupted_attempts": 1,
    "git_subprocess_unknown_attempt_count": 1,
    "network_clone_unknown_attempt_count": 1,
    "network_fetch_unknown_attempt_count": 1,
    "network_materialized_bytes_unknown_attempt_count": 1,
}


def historical_scan_usage():
    proof_rows = [
        {
            "run_id": "predecessor",
            "task_id": "task-1",
            "task_key": "scan:one",
            "attempt": 1,
            "repository_id": "R_one",
            "full_name": "public/one",
            "head_sha": "1" * 40,
            "task_payload_sha256": "1" * 64,
            "method": "scan-attempt-ledger-v1",
            "usage": {
                "seconds": 10.0,
                "current_tree_triage_seconds": 2.0,
                "history_dating_seconds": 6.0,
                "analysis_seconds": 2.0,
                "git_subprocess_count": 7,
                "network_clone_count": 1,
                "network_fetch_count": 1,
                "network_materialized_bytes": 100,
            },
            "evidence": {
                "attempt_status": "complete",
                "retryable": None,
                "error_code": None,
                "started_at": "2026-07-30T00:00:00Z",
                "finished_at": "2026-07-30T00:00:10Z",
            },
        },
        {
            "run_id": "predecessor",
            "task_id": "task-2",
            "task_key": "scan:two",
            "attempt": 1,
            "repository_id": "R_two",
            "full_name": "public/two",
            "head_sha": "2" * 40,
            "task_payload_sha256": "2" * 64,
            "method": "pre-v5-public-cache-disk-upper-v1",
            "usage": {
                "seconds": None,
                "current_tree_triage_seconds": None,
                "history_dating_seconds": None,
                "analysis_seconds": None,
                "git_subprocess_count": None,
                "network_clone_count": None,
                "network_fetch_count": None,
                "network_materialized_bytes": 200,
            },
            "evidence": {
                "bound_method": (
                    "max-public-disk-usage-and-exact-head-cache-v1"
                ),
                "public_repository_metadata_sha256": "3" * 64,
                "cache_metadata_sha256": "4" * 64,
                "cache_key": "5" * 64,
                "disk_usage_kb": 0,
                "public_disk_usage_bytes": 0,
                "cache_accounted_bytes": 200,
                "network_materialized_bytes_upper_bound": 200,
                "predecessor_lfs_transfer_bound_sha256": "6" * 64,
            },
        },
    ]
    document = {
        "version": 1,
        "predecessor_run_id": "predecessor",
        "predecessor_plan_sha256": "a" * 64,
        "predecessor_lineage_sha256": "b" * 64,
        "attempt_count": 2,
        "exact_attempt_count": 1,
        "conservative_attempt_count": 1,
        "timing_known_attempt_count": 1,
        "timing_unknown_attempt_count": 1,
        "usage": {
            "seconds": 10.0,
            "current_tree_triage_seconds": 2.0,
            "history_dating_seconds": 6.0,
            "analysis_seconds": 2.0,
            "git_subprocess_count": 7,
            "git_subprocess_unknown_attempt_count": 1,
            "network_clone_count": 1,
            "network_clone_unknown_attempt_count": 1,
            "network_fetch_count": 1,
            "network_fetch_unknown_attempt_count": 1,
            # Includes the successor's reviewed upper bound for attempt 2.
            "network_materialized_bytes": 300,
        },
        "proof_rows": proof_rows,
        "proof_rows_sha256": _canonical_sha256(proof_rows),
    }
    document["contract_sha256"] = _canonical_sha256(document)
    return document


def reviewed_contract(history=None):
    selected = {"cublas"}
    active = {library["id"] for library in config.LIBRARIES}
    return {
        "mode": "reconcile",
        "run_class": "phase8-cohort-a",
        "release_scope": "partial-portfolio",
        "release_label": "Phase 8 Cohort A",
        "selected_library_ids": sorted(selected),
        "excluded_library_ids": sorted(active - selected),
        "metadata_batch_size": 50,
        "network_task_source_sha256": _network_task_source_sha256(),
        "historical_network_request_attempts": {
            "github-code-search": 0,
            "sourcegraph": 0,
        },
        "historical_scan_usage": (
            historical_scan_usage() if history is None else history
        ),
        "historical_graphql_usage": {
            "request_count": 0,
            "points_used": 0,
            "remaining": None,
            "reset_at": None,
        },
        "historical_wall_seconds": 0,
        "reviewed_slo": {
            "class": "partial_cohort_reconciliation",
            "target_seconds": 24 * 3600,
            "ceiling_seconds": 36 * 3600,
        },
    }


class HistoricalScanUsageTests(unittest.TestCase):
    def test_current_interruption_remains_unknown_when_combined(self):
        combined = _combine_scan_attempt_usage(
            CURRENT_USAGE_WITH_UNKNOWN,
            historical_scan_usage(),
        )
        self.assertEqual(combined["attempt_count"], 4)
        self.assertEqual(combined["exact_attempt_count"], 2)
        self.assertEqual(combined["irreconstructible_attempt_count"], 1)
        self.assertEqual(combined["timing_unknown_attempt_count"], 2)
        self.assertEqual(
            combined["network_fetch_unknown_attempt_count"], 2
        )
        self.assertEqual(combined["current"]["attempt_count"], 2)

    def test_owner_checkpoint_usage_remains_unknown_never_zero(self):
        policy = {
            **_CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY,
            "policy_sha256": _sha256(
                _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY
            ),
        }
        row = {
            "run_id": policy["predecessor_run_id"],
            "task_id": "99",
            "task_key": "scan:unknown",
            "attempt": 1,
            "repository_id": "R_unknown",
            "full_name": "public/unknown",
            "head_sha": "9" * 40,
            "task_payload_sha256": "9" * 64,
            "method": "owner-authorized-irreconstructible-v1",
            "usage": {
                "seconds": None,
                "current_tree_triage_seconds": None,
                "history_dating_seconds": None,
                "analysis_seconds": None,
                "git_subprocess_count": None,
                "network_clone_count": None,
                "network_fetch_count": None,
                "network_materialized_bytes": None,
            },
            "evidence": {
                "policy_id": policy["policy_id"],
                "attempt_status": policy["required_status"],
                "error_code": policy["required_error_code"],
                "usage_complete": False,
                "started_at": "2026-07-31T05:30:00Z",
                "finished_at": "2026-07-31T06:07:47Z",
            },
        }
        proof_rows = [row] * policy["expected_attempt_count"]
        for ordinal, proof in enumerate(proof_rows):
            proof_rows[ordinal] = {
                **proof,
                "task_id": str(100 + ordinal),
                "task_key": "scan:unknown:%d" % ordinal,
                "repository_id": "R_unknown_%d" % ordinal,
                "full_name": "public/unknown-%d" % ordinal,
            }
        usage = {
            "seconds": 0.0,
            "current_tree_triage_seconds": 0.0,
            "history_dating_seconds": 0.0,
            "analysis_seconds": 0.0,
            "git_subprocess_count": 0,
            "git_subprocess_unknown_attempt_count": len(proof_rows),
            "network_clone_count": 0,
            "network_clone_unknown_attempt_count": len(proof_rows),
            "network_fetch_count": 0,
            "network_fetch_unknown_attempt_count": len(proof_rows),
            "network_materialized_bytes": 0,
            "network_materialized_bytes_unknown_attempt_count": len(
                proof_rows
            ),
        }
        contract = {
            "version": 2,
            "predecessor_run_id": policy["predecessor_run_id"],
            "predecessor_plan_sha256": "a" * 64,
            "predecessor_lineage_sha256": "b" * 64,
            "attempt_count": len(proof_rows),
            "exact_attempt_count": 0,
            "conservative_attempt_count": 0,
            "irreconstructible_attempt_count": len(proof_rows),
            "timing_known_attempt_count": 0,
            "timing_unknown_attempt_count": len(proof_rows),
            "usage": usage,
            "proof_rows": proof_rows,
            "proof_rows_sha256": _canonical_sha256(proof_rows),
            "unknown_usage_policy": policy,
        }
        contract["contract_sha256"] = _canonical_sha256(contract)
        validated = _validate_historical_scan_usage(contract)
        self.assertEqual(14, validated["irreconstructible_attempt_count"])
        combined = _combine_scan_attempt_usage(CURRENT_USAGE, validated)
        self.assertEqual(
            14,
            combined["network_materialized_bytes_unknown_attempt_count"],
        )
        invented = copy.deepcopy(contract)
        invented["proof_rows"][0]["usage"][
            "network_materialized_bytes"
        ] = 0
        invented["proof_rows_sha256"] = _canonical_sha256(
            invented["proof_rows"]
        )
        invented["contract_sha256"] = _canonical_sha256({
            key: value
            for key, value in invented.items()
            if key != "contract_sha256"
        })
        with self.assertRaisesRegex(PipelineError, "invented usage"):
            _validate_historical_scan_usage(invented)

    def test_reviewed_contract_requires_valid_hashed_history(self):
        contract = reviewed_contract()
        validated = _validate_reviewed_execution_contract(
            contract,
            mode="reconcile",
            wanted={"cublas"},
            budgets=RunBudgets.reconcile(),
            metadata_batch_size=50,
        )
        self.assertEqual(
            validated["historical_scan_usage"]["contract_sha256"],
            contract["historical_scan_usage"]["contract_sha256"],
        )

        missing = copy.deepcopy(contract)
        missing.pop("historical_scan_usage")
        with self.assertRaisesRegex(
            PipelineError, "execution contract shape"
        ):
            _validate_reviewed_execution_contract(
                missing,
                mode="reconcile",
                wanted={"cublas"},
                budgets=RunBudgets.reconcile(),
                metadata_batch_size=50,
            )

        for mutation, message in (
            (
                lambda value: value.update({"attempt_count": 3}),
                "attempt counts",
            ),
            (
                lambda value: value.update(
                    {"proof_rows_sha256": "c" * 64}
                ),
                "proof-row digest",
            ),
            (
                lambda value: value.update(
                    {"contract_sha256": "d" * 64}
                ),
                "contract digest",
            ),
        ):
            with self.subTest(message=message):
                malformed = historical_scan_usage()
                mutation(malformed)
                with self.assertRaisesRegex(PipelineError, message):
                    _validate_historical_scan_usage(malformed)

        # Re-signing both enclosing hashes cannot legitimize an undercharge.
        undercharged = historical_scan_usage()
        undercharged["proof_rows"][1]["usage"][
            "network_materialized_bytes"
        ] = 1
        undercharged["proof_rows_sha256"] = _canonical_sha256(
            undercharged["proof_rows"]
        )
        undercharged["contract_sha256"] = _canonical_sha256({
            key: value
            for key, value in undercharged.items()
            if key != "contract_sha256"
        })
        with self.assertRaisesRegex(
            PipelineError, "conservative byte proof"
        ):
            _validate_historical_scan_usage(undercharged)

        # Re-signing an internally valid row still cannot hide lower totals.
        omitted_total = historical_scan_usage()
        omitted_total["usage"]["network_materialized_bytes"] = 100
        omitted_total["contract_sha256"] = _canonical_sha256({
            key: value
            for key, value in omitted_total.items()
            if key != "contract_sha256"
        })
        with self.assertRaisesRegex(
            PipelineError, "totals do not match proof rows"
        ):
            _validate_historical_scan_usage(omitted_total)

        reordered = historical_scan_usage()
        reordered["proof_rows"].reverse()
        reordered["proof_rows_sha256"] = _canonical_sha256(
            reordered["proof_rows"]
        )
        reordered["contract_sha256"] = _canonical_sha256({
            key: value
            for key, value in reordered.items()
            if key != "contract_sha256"
        })
        with self.assertRaisesRegex(PipelineError, "not canonical"):
            _validate_historical_scan_usage(reordered)

        duplicate = historical_scan_usage()
        duplicate["proof_rows"][1].update({
            "run_id": duplicate["proof_rows"][0]["run_id"],
            "task_id": duplicate["proof_rows"][0]["task_id"],
            "attempt": duplicate["proof_rows"][0]["attempt"],
        })
        duplicate["proof_rows_sha256"] = _canonical_sha256(
            duplicate["proof_rows"]
        )
        duplicate["contract_sha256"] = _canonical_sha256({
            key: value
            for key, value in duplicate.items()
            if key != "contract_sha256"
        })
        with self.assertRaisesRegex(PipelineError, "duplicates"):
            _validate_historical_scan_usage(duplicate)

    def test_combination_charges_conservative_history_exactly_once(self):
        history = historical_scan_usage()

        first = _combine_scan_attempt_usage(CURRENT_USAGE, history)
        second = _combine_scan_attempt_usage(CURRENT_USAGE, history)

        self.assertEqual(first, second)
        self.assertEqual(first["historical"]["attempt_count"], 2)
        self.assertEqual(
            first["historical"]["conservative_attempt_count"], 1
        )
        self.assertEqual(first["current"]["attempt_count"], 1)
        self.assertEqual(first["combined"]["attempt_count"], 3)
        self.assertEqual(first["attempt_count"], 3)
        self.assertEqual(
            first["combined"]["network_materialized_bytes"], 350
        )
        self.assertEqual(first["network_materialized_bytes"], 350)
        self.assertEqual(
            first["combined"]["timing_unknown_attempt_count"], 1
        )
        with self.assertRaisesRegex(PipelineError, "uncombined"):
            _combine_scan_attempt_usage(first, history)
        for mutation in (
            lambda value: value.update({"usage_complete": False}),
            lambda value: value.update({"attempt_count": 2}),
            lambda value: value.update(
                {"network_materialized_bytes": 1.5}
            ),
        ):
            with self.subTest(mutation=mutation):
                malformed = copy.deepcopy(CURRENT_USAGE)
                mutation(malformed)
                with self.assertRaisesRegex(
                    PipelineError, "current scan attempt"
                ):
                    _combine_scan_attempt_usage(malformed, history)

    def test_resume_recomputes_without_copying_predecessor_rows(self):
        history = historical_scan_usage()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            with StateDB(path) as state:
                state.upsert_repository(
                    {
                        "node_id": "R_public",
                        "full_name": "public/example",
                        "visibility": "public",
                        "head_sha": HEAD_SHA,
                    }
                )
                state.create_run(
                    "successor",
                    mode="reconcile",
                    plan={
                        "execution_contract": {
                            "historical_scan_usage": history,
                        },
                        "successor_lineage": {
                            "historical_scan_usage_sha256": (
                                history["contract_sha256"]
                            ),
                        },
                    },
                    status="running",
                )
                task_id = state.enqueue_task(
                    "successor",
                    "scan",
                    "current-task",
                    repository_id="R_public",
                    payload={"head_sha": HEAD_SHA},
                )
                state.lease_task_by_id(
                    task_id, worker="worker", now_epoch=100
                )
                state.complete_task(
                    task_id,
                    worker="worker",
                    result=CURRENT_USAGE,
                    now_epoch=101,
                )
                first = _scan_attempt_usage_for_run(
                    state, "successor"
                )
                self.assertEqual(
                    state.connection.execute(
                        "SELECT COUNT(*) FROM scan_attempts"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    state.connection.execute(
                        "SELECT COUNT(*) FROM scan_results"
                    ).fetchone()[0],
                    0,
                )

            with StateDB(path) as resumed:
                second = _scan_attempt_usage_for_run(
                    resumed, "successor"
                )

            self.assertEqual(first, second)
            self.assertEqual(second["historical"]["attempt_count"], 2)
            self.assertEqual(second["current"]["attempt_count"], 1)
            self.assertEqual(second["combined"]["attempt_count"], 3)
            self.assertEqual(
                second["combined"]["network_materialized_bytes"], 350
            )

    def test_lineage_digest_mismatch_fails_closed(self):
        history = historical_scan_usage()
        with tempfile.TemporaryDirectory() as temporary:
            with StateDB(Path(temporary) / "state.sqlite3") as state:
                state.create_run(
                    "successor",
                    mode="reconcile",
                    plan={
                        "execution_contract": {
                            "historical_scan_usage": history,
                        },
                        "successor_lineage": {
                            "historical_scan_usage_sha256": "f" * 64,
                        },
                    },
                    status="running",
                )
                with self.assertRaisesRegex(
                    PipelineError, "lineage digest"
                ):
                    _scan_attempt_usage_for_run(state, "successor")

                state.create_run(
                    "missing-digest",
                    mode="reconcile",
                    plan={
                        "execution_contract": {
                            "historical_scan_usage": history,
                        },
                        "successor_lineage": {"kind": "cohort"},
                    },
                    status="running",
                )
                with self.assertRaisesRegex(
                    PipelineError, "lineage digest"
                ):
                    _scan_attempt_usage_for_run(
                        state, "missing-digest"
                    )

    def test_historical_usage_enforces_both_hard_budgets(self):
        usage = _combine_scan_attempt_usage(
            CURRENT_USAGE, historical_scan_usage()
        )
        exact = dataclasses.replace(
            RunBudgets.weekly(),
            max_fetches=4,
            max_git_materialized_bytes=350,
        )
        _enforce_scan_attempt_budgets(
            usage, planned_attempts=1, budgets=exact
        )

        with self.assertRaisesRegex(BudgetExceeded, "fetch budget"):
            _enforce_scan_attempt_budgets(
                usage,
                planned_attempts=2,
                budgets=exact,
            )
        byte_exhausted = dataclasses.replace(
            exact, max_git_materialized_bytes=349
        )
        with self.assertRaisesRegex(
            BudgetExceeded, "materialization byte budget"
        ):
            _enforce_scan_attempt_budgets(
                usage,
                planned_attempts=0,
                budgets=byte_exhausted,
            )

    def test_runtime_report_separates_historical_current_and_combined(self):
        combined = _combine_scan_attempt_usage(
            CURRENT_USAGE, historical_scan_usage()
        )
        with tempfile.TemporaryDirectory() as temporary:
            pipeline = CollectorPipeline(repo_root=temporary)
            pipeline._scan_attempt_usage = combined
            report = pipeline._runtime_report(
                mode="reconcile",
                run_class="phase8-cohort-a",
                release_scope="partial-portfolio",
                started=0,
                budgets=RunBudgets.reconcile(),
                outcomes=[],
                cache_before_bytes=0,
                cache_before_keys=frozenset(),
                discovery_metrics={},
                resolution=types.SimpleNamespace(
                    request_count=0,
                    points_used=0,
                    remaining=5000,
                ),
                final_visibility={
                    "run_graphql_requests": 0,
                    "run_graphql_points": 0,
                    "run_graphql_remaining": 5000,
                    "run_graphql_reset_at": None,
                },
                artifacts=(),
                stage_durations={},
                task_inventory={},
            )

        self.assertEqual(
            report["scan"]["attempt_counts"],
            {"historical": 2, "current": 1, "combined": 3},
        )
        self.assertEqual(
            report["scan"]["git_materialized_bytes_by_origin"],
            {"historical": 300, "current": 50, "combined": 350},
        )
        self.assertEqual(
            report["scan"]["attempt_usage"]["historical"][
                "contract_sha256"
            ],
            historical_scan_usage()["contract_sha256"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
