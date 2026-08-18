"""Focused successor proofs for the content/diagnostic remediation."""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from collector import config
from collector.discovery import (
    CoverageCertificate,
    DiscoveryObservation,
    DiscoveryResult,
)
from collector.fingerprints import fingerprint
from collector.github_client import (
    GraphQLResolution,
    RepositoryMetadata,
)
from collector.pipeline import (
    PipelineError,
    RunBudgets,
    _discovery_result_to_task_result,
    _metadata_result_to_task_result,
)
from collector.planner import build_plan
from collector.state import StateDB
from collector.successor import (
    _CONTENT_DIAGNOSTIC_ADDED_PATHS,
    _CONTENT_DIAGNOSTIC_PRODUCTION_PATHS,
    _CONTENT_DIAGNOSTIC_REQUIRED_SUPPORT_PATHS,
    _CONTENT_DIAGNOSTIC_REMEDIATION_KIND,
    _CONTENT_DIAGNOSTIC_REMEDIATION_PROFILE,
    _CONTENT_DIAGNOSTIC_SUCCESSOR_NORMALIZED_SHA256,
    _CONTENT_DIAGNOSTIC_SUCCESSOR_SOURCE_SHA256,
    _CONTENT_DIAGNOSTIC_SUPPORT_PATHS,
    _assert_content_diagnostic_fingerprint_contract,
    _assert_content_diagnostic_paths,
    _assert_content_diagnostic_source_bytes,
    _assert_exact_network_task_semantics,
    _derive_historical_scan_usage,
    _assert_reviewed_source_sha256,
    _discovery_specs,
    _sha256,
    _reviewed_semantic_changes,
    _task_key,
    _validate_historical_scan_usage_contract,
    prepare_phase8_cohort_successor,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.datetime(2026, 7, 30, tzinfo=datetime.timezone.utc)


def _complete_task(state: StateDB, task_id: int, document: dict) -> None:
    leased = state.lease_task_by_id(
        task_id, worker="fixture", lease_seconds=300
    )
    if leased is None:
        raise AssertionError("fixture task was not leaseable")
    state.complete_task(task_id, worker="fixture", result=document)


def _discovery_document(spec: dict) -> dict:
    observation = DiscoveryObservation(
        repo_full_name="public/example",
        library_id=spec["library_id"],
        signal_id=spec["signal_id"],
        source=spec["source"],
        query_fingerprint=spec["query_fingerprint"],
        observed_at=NOW,
        visibility="PUBLIC",
        matched_path="src/example.cu",
    )
    return _discovery_result_to_task_result(
        DiscoveryResult(
            observations=(observation,),
            quarantined_observations=(),
            certificate=CoverageCertificate(
                source=spec["source"],
                library_id=spec["library_id"],
                query_fingerprint=spec["query_fingerprint"],
                epoch_started_at=NOW,
                epoch_completed_at=NOW,
                complete=True,
                terminal=True,
                observations_count=1,
                quarantined_count=0,
                gaps=(),
                metrics={"request_count": 1},
            ),
        )
    )


def _metadata_fixture() -> tuple[str, dict, dict]:
    payload = {
        "version": 1,
        "lookups": [{
            "node_id": None,
            "full_name": "public/example",
        }],
    }
    result = _metadata_result_to_task_result(
        GraphQLResolution(
            repositories=(
                RepositoryMetadata(
                    request_key="name:public/example",
                    requested_node_id=None,
                    requested_full_name="public/example",
                    node_id="R_current",
                    full_name="public/example",
                    visibility="PUBLIC",
                    is_private=False,
                    is_fork=False,
                    is_archived=False,
                    default_branch="main",
                    head_oid="a" * 40,
                    renamed=False,
                    status="ok",
                ),
            ),
            errors=(),
            request_count=1,
            points_used=1,
            remaining=5000,
            reset_at="2026-07-30T00:00:00Z",
        )
    )
    task_key = "batch:%06d:%s" % (
        0,
        fingerprint("github-metadata-task", payload)[:32],
    )
    return task_key, payload, result


def _scan_usage(**overrides) -> dict:
    value = {
        "status": "match",
        "seconds": 12.5,
        "current_tree_triage_seconds": 5.25,
        "history_dating_seconds": 4.0,
        "analysis_seconds": 1.5,
        "git_subprocess_count": 17,
        "network_clone_count": 1,
        "network_fetch_count": 3,
        "network_materialized_bytes": 4096,
    }
    value.update(overrides)
    return value


def _lfs_transfer_bound_proof() -> dict:
    proof = {
        "version": 1,
        "predecessor_source_commit": "a" * 40,
        "scan_source_sha256": "1" * 64,
        "repo_cache_source_sha256": "2" * 64,
        "git_auth_env_semantic_sha256": "3" * 64,
        "repo_cache_run_semantic_sha256": "4" * 64,
        "repo_cache_checkout_semantic_sha256": "5" * 64,
        "git_lfs_skip_smudge": "1",
        "public_lfs_hydration": "absent",
    }
    proof["contract_sha256"] = _sha256(proof)
    return proof


def _pre_v5_scan_fixture(
    state: StateDB,
    *,
    result: dict | None,
    attempts: int = 1,
    disk_usage_kb: int = 10,
) -> tuple[int, str, str]:
    full_name = "public/scan-fixture"
    head_sha = "c" * 40
    repository_id = "R_scan_fixture"
    state.upsert_repository({
        "node_id": repository_id,
        "full_name": full_name,
        "visibility": "PUBLIC",
        "is_fork": False,
        "is_archived": False,
        "head_sha": head_sha,
        "metadata": {
            "explicitly_public": True,
            "is_private": False,
            "visibility": "PUBLIC",
            "node_id": repository_id,
            "full_name": full_name,
            "head_oid": head_sha,
            "disk_usage_kb": disk_usage_kb,
        },
    })
    state.create_run(
        "predecessor",
        mode="reconcile",
        plan={},
        budgets={},
        fingerprints={},
        base_release_id="fixture-release",
        status="running",
    )
    task_id = state.enqueue_task(
        "predecessor",
        "scan",
        "scan-fixture",
        repository_id=repository_id,
        payload={
            "node_id": repository_id,
            "full_name": full_name,
            "head_sha": head_sha,
            "libraries": ["cublas"],
        },
    )
    state.connection.execute(
        """
        UPDATE tasks
        SET status=?, attempts=?, result_json=?, error_code=?
        WHERE task_id=?
        """,
        (
            "complete" if result is not None else "failed",
            attempts,
            (
                json.dumps(result, sort_keys=True, separators=(",", ":"))
                if result is not None
                else None
            ),
            None if result is not None else "interrupted",
            task_id,
        ),
    )
    return task_id, full_name, head_sha


class ContentSuccessorTests(unittest.TestCase):
    def test_profile_has_exact_production_and_added_path_contract(self):
        self.assertEqual(
            "evidence-content-and-attempt-diagnostics",
            _CONTENT_DIAGNOSTIC_REMEDIATION_KIND,
        )
        self.assertEqual(
            {"collector/evidence_content.py"},
            set(_CONTENT_DIAGNOSTIC_ADDED_PATHS),
        )
        self.assertEqual(
            {
                "collector/evidence_content.py",
                "collector/pipeline.py",
                "collector/planner.py",
                "collector/repo_cache.py",
                "collector/scan.py",
                "collector/scanner_v2.py",
                "collector/state.py",
                "collector/state_migrations.py",
                "collector/successor.py",
                "collector/triage.py",
            },
            set(_CONTENT_DIAGNOSTIC_PRODUCTION_PATHS),
        )
        self.assertEqual(
            set(_CONTENT_DIAGNOSTIC_PRODUCTION_PATHS),
            set(_CONTENT_DIAGNOSTIC_REMEDIATION_PROFILE),
        )
        for nodes in _CONTENT_DIAGNOSTIC_REMEDIATION_PROFILE.values():
            self.assertEqual(tuple(sorted(nodes)), nodes)
        self.assertEqual(
            set(_CONTENT_DIAGNOSTIC_PRODUCTION_PATHS)
            - {"collector/successor.py"},
            set(_CONTENT_DIAGNOSTIC_SUCCESSOR_SOURCE_SHA256),
        )
        for source_hash in (
            *(_CONTENT_DIAGNOSTIC_SUCCESSOR_SOURCE_SHA256.values()),
            _CONTENT_DIAGNOSTIC_SUCCESSOR_NORMALIZED_SHA256,
        ):
            self.assertEqual(64, len(source_hash))
            self.assertTrue(
                all(
                    character in "0123456789abcdef"
                    for character in source_hash
                )
            )
        # The historical profile remains immutable after a later, separately
        # audited parser successor. It must reject the evolved current tree
        # instead of silently moving its frozen source hashes.
        with self.assertRaisesRegex(
            PipelineError,
            "collector/evidence_content.py",
        ):
            _assert_content_diagnostic_source_bytes(ROOT)

    def test_path_contract_refuses_missing_or_extra_production_source(self):
        exact = tuple(
            sorted(
                set(_CONTENT_DIAGNOSTIC_PRODUCTION_PATHS)
                | set(_CONTENT_DIAGNOSTIC_REQUIRED_SUPPORT_PATHS)
            )
        )
        _assert_content_diagnostic_paths(exact)

        with self.assertRaisesRegex(
            PipelineError, "inexact production source set"
        ):
            _assert_content_diagnostic_paths(
                tuple(
                    path
                    for path in exact
                    if path != "collector/state.py"
                )
            )
        with self.assertRaisesRegex(
            PipelineError, "inexact production source set"
        ):
            _assert_content_diagnostic_paths(
                tuple(sorted(set(exact) | {"collector/cli.py"}))
            )
        with self.assertRaisesRegex(
            PipelineError, "unreviewed support paths"
        ):
            _assert_content_diagnostic_paths(
                tuple(sorted(set(exact) | {"notes/unreviewed.md"}))
            )
        self.assertIn(
            "ops/req14_detector_fingerprints.json",
            _CONTENT_DIAGNOSTIC_SUPPORT_PATHS,
        )

    def test_semantic_audit_proves_new_module_was_not_in_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "collector").mkdir()
            subprocess.run(
                ["git", "init", "-q"],
                cwd=root,
                check=True,
            )
            (root / "collector" / "existing.py").write_text(
                "VALUE = 1\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["git", "add", "collector/existing.py"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.com",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=root,
                check=True,
            )
            predecessor = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            (root / "collector" / "new.py").write_text(
                "def parse(value):\n    return value\n",
                encoding="utf-8",
            )
            changes = _reviewed_semantic_changes(
                root,
                predecessor,
                {"collector/new.py": ("parse",)},
                added_paths=frozenset({"collector/new.py"}),
            )
            self.assertEqual(
                {"collector/new.py": ["parse"]},
                changes,
            )
            with self.assertRaisesRegex(
                PipelineError, "expected an added source path"
            ):
                _reviewed_semantic_changes(
                    root,
                    predecessor,
                    {"collector/existing.py": ("<module>.Assign:1",)},
                    added_paths=frozenset({"collector/existing.py"}),
                )

    def test_reviewed_source_bytes_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "collector" / "reviewed.py"
            source.parent.mkdir()
            source.write_bytes(b"VALUE = 1\n")
            expected = {
                "collector/reviewed.py": hashlib.sha256(
                    source.read_bytes()
                ).hexdigest()
            }
            self.assertEqual(
                expected,
                _assert_reviewed_source_sha256(root, expected),
            )
            source.write_bytes(b"VALUE = 2\n")
            with self.assertRaisesRegex(
                PipelineError, "changed reviewed source bytes"
            ):
                _assert_reviewed_source_sha256(root, expected)

    def test_raw_pipeline_change_can_preserve_exact_task_execution(self):
        predecessor = (ROOT / "collector" / "pipeline.py").read_bytes()
        successor = predecessor + (
            b"\n\ndef _fixture_only_attempt_diagnostic():\n"
            b"    return 'diagnostic-only'\n"
        )
        self.assertNotEqual(
            hashlib.sha256(predecessor).digest(),
            hashlib.sha256(successor).digest(),
        )
        proof = _assert_exact_network_task_semantics(
            predecessor,
            successor,
        )
        self.assertTrue(proof["exact_discovery_task_execution"])
        self.assertTrue(proof["exact_metadata_task_execution"])

    def test_task_semantic_changes_fail_closed(self):
        predecessor = (ROOT / "collector" / "pipeline.py").read_bytes()
        discovery_change = predecessor.replace(
            b"completed discovery task has no valid request count",
            b"completed discovery task has a different request count",
            1,
        )
        self.assertNotEqual(predecessor, discovery_change)
        with self.assertRaisesRegex(
            PipelineError, "changed discovery task semantics"
        ):
            _assert_exact_network_task_semantics(
                predecessor,
                discovery_change,
            )

        metadata_change = predecessor.replace(
            b"GitHub metadata batch did not exactly ",
            b"GitHub metadata batch did not fully ",
            1,
        )
        self.assertNotEqual(predecessor, metadata_change)
        with self.assertRaisesRegex(
            PipelineError, "changed metadata task semantics"
        ):
            _assert_exact_network_task_semantics(
                predecessor,
                metadata_change,
            )

    def test_every_detector_must_change_and_old_scan_reuse_is_forbidden(self):
        current = {
            "libraries": {
                "cublas": {"detector": "new-a"},
                "cutensor": {"detector": "new-b"},
            }
        }
        audit = {
            "detector_only_changes": {
                "cublas": {
                    "predecessor": "old-a",
                    "successor": "new-a",
                },
                "cutensor": {
                    "predecessor": "old-b",
                    "successor": "new-b",
                },
            },
            "scan_reuse_compatible": False,
        }
        proof = _assert_content_diagnostic_fingerprint_contract(
            audit, current
        )
        self.assertEqual(2, proof["changed_detector_count"])
        self.assertFalse(proof["old_scan_reuse_allowed"])

        incomplete = {
            **audit,
            "detector_only_changes": {
                "cublas": audit["detector_only_changes"]["cublas"],
            },
        }
        with self.assertRaisesRegex(
            PipelineError, "exact detector universe"
        ):
            _assert_content_diagnostic_fingerprint_contract(
                incomplete, current
            )
        with self.assertRaisesRegex(
            PipelineError, "cannot reuse old scans"
        ):
            _assert_content_diagnostic_fingerprint_contract(
                {**audit, "scan_reuse_compatible": True},
                current,
            )

    def test_historical_scan_usage_charges_exact_pre_v5_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "state.sqlite3"
            with StateDB(state_path) as state:
                _pre_v5_scan_fixture(state, result=_scan_usage())
                contract = _derive_historical_scan_usage(
                    state=state,
                    predecessor_run_id="predecessor",
                    predecessor_plan={"execution_contract": {}},
                    cache_root=root / "cache",
                )
            self.assertEqual(1, contract["attempt_count"])
            self.assertEqual(1, contract["exact_attempt_count"])
            self.assertEqual(0, contract["conservative_attempt_count"])
            self.assertEqual(
                {
                    "seconds": 12.5,
                    "current_tree_triage_seconds": 5.25,
                    "history_dating_seconds": 4.0,
                    "analysis_seconds": 1.5,
                    "git_subprocess_count": 17,
                    "git_subprocess_unknown_attempt_count": 0,
                    "network_clone_count": 1,
                    "network_clone_unknown_attempt_count": 0,
                    "network_fetch_count": 3,
                    "network_fetch_unknown_attempt_count": 0,
                    "network_materialized_bytes": 4096,
                    "network_materialized_bytes_unknown_attempt_count": 0,
                },
                contract["usage"],
            )
            self.assertEqual(
                "pre-v5-task-result-v1",
                contract["proof_rows"][0]["method"],
            )

    def test_historical_scan_usage_refuses_malformed_or_negative_metrics(self):
        cases = (
            {"status": "match"},
            _scan_usage(network_materialized_bytes=-1),
        )
        for ordinal, result in enumerate(cases):
            with self.subTest(ordinal=ordinal):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    with StateDB(root / "state.sqlite3") as state:
                        _pre_v5_scan_fixture(state, result=result)
                        with self.assertRaisesRegex(
                            PipelineError,
                            "usage is incomplete or invalid",
                        ):
                            _derive_historical_scan_usage(
                                state=state,
                                predecessor_run_id="predecessor",
                                predecessor_plan={
                                    "execution_contract": {}
                                },
                                cache_root=root / "cache",
                            )

    def test_historical_scan_usage_bounds_unknown_pre_v5_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache_root = root / "cache"
            (cache_root / "repos").mkdir(parents=True)
            with StateDB(root / "state.sqlite3") as state:
                _task_id, full_name, head_sha = _pre_v5_scan_fixture(
                    state,
                    result=None,
                    disk_usage_kb=10,
                )
                cache_key = hashlib.sha256(
                    full_name.lower().encode("utf-8")
                ).hexdigest()
                (cache_root / "repos" / (cache_key + ".json")).write_text(
                    json.dumps({
                        "full_name": full_name,
                        "head_sha": head_sha,
                        "bytes": 20_000,
                        "reserved_growth_bytes": 5_000,
                    }),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    PipelineError, "LFS transfer proof"
                ):
                    _derive_historical_scan_usage(
                        state=state,
                        predecessor_run_id="predecessor",
                        predecessor_plan={"execution_contract": {}},
                        cache_root=cache_root,
                    )
                lfs_proof = _lfs_transfer_bound_proof()
                contract = _derive_historical_scan_usage(
                    state=state,
                    predecessor_run_id="predecessor",
                    predecessor_plan={"execution_contract": {}},
                    cache_root=cache_root,
                    predecessor_lfs_transfer_bound=lfs_proof,
                )
            self.assertEqual(1, contract["conservative_attempt_count"])
            self.assertEqual(1, contract["timing_unknown_attempt_count"])
            self.assertEqual(0, contract["usage"]["network_clone_count"])
            self.assertEqual(
                1,
                contract["usage"]["network_clone_unknown_attempt_count"],
            )
            self.assertEqual(0, contract["usage"]["network_fetch_count"])
            self.assertEqual(
                1,
                contract["usage"]["network_fetch_unknown_attempt_count"],
            )
            self.assertEqual(
                25_000,
                contract["usage"]["network_materialized_bytes"],
            )
            row = contract["proof_rows"][0]
            self.assertIsNone(row["usage"]["seconds"])
            self.assertIsNone(row["usage"]["network_clone_count"])
            self.assertEqual(
                lfs_proof["contract_sha256"],
                row["evidence"][
                    "predecessor_lfs_transfer_bound_sha256"
                ],
            )

    def test_historical_scan_usage_refuses_unknown_without_safe_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with StateDB(root / "state.sqlite3") as state:
                _pre_v5_scan_fixture(state, result=None)
                with self.assertRaisesRegex(
                    PipelineError, "safe exact-head cache metadata"
                ):
                    _derive_historical_scan_usage(
                        state=state,
                        predecessor_run_id="predecessor",
                        predecessor_plan={"execution_contract": {}},
                        cache_root=root / "missing-cache",
                        predecessor_lfs_transfer_bound=(
                            _lfs_transfer_bound_proof()
                        ),
                    )

    def test_historical_scan_usage_digest_is_stable_and_self_validating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with StateDB(root / "state.sqlite3") as state:
                _pre_v5_scan_fixture(state, result=_scan_usage())
                arguments = {
                    "state": state,
                    "predecessor_run_id": "predecessor",
                    "predecessor_plan": {
                        "execution_contract": {},
                        "successor_lineage": {"version": 1},
                    },
                    "cache_root": root / "cache",
                }
                first = _derive_historical_scan_usage(**arguments)
                second = _derive_historical_scan_usage(**arguments)
            self.assertEqual(first, second)
            self.assertEqual(
                first,
                _validate_historical_scan_usage_contract(first),
            )
            changed = copy.deepcopy(first)
            changed["usage"]["seconds"] += 1
            with self.assertRaisesRegex(
                PipelineError, "totals do not match"
            ):
                _validate_historical_scan_usage_contract(changed)

    def test_successor_inherits_exact_certificates_but_no_old_scans(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            (data / "v2").mkdir(parents=True)
            (data / "v2" / "manifest.json").write_text(
                json.dumps({"release": {"id": "fixture-release"}}),
                encoding="utf-8",
            )
            state_path = root / "collector.sqlite3"
            budgets = RunBudgets.reconcile()
            selected = ["cublas"]
            active = sorted(item["id"] for item in config.LIBRARIES)
            excluded = sorted(set(active) - set(selected))
            plan = build_plan(
                mode="reconcile",
                state_path=state_path,
                data_dir=data,
                libraries=list(config.LIBRARIES),
                weekly_scan_budget=budgets.max_scan_repositories,
                max_graphql_points=budgets.max_graphql_points,
                min_graphql_remaining=budgets.min_graphql_remaining,
            )
            current_fingerprints = plan.fingerprints.as_dict()
            predecessor_fingerprints = copy.deepcopy(
                current_fingerprints
            )
            for values in predecessor_fingerprints["libraries"].values():
                values["detector"] = "0" * 64
            old_executable = "a" * 64
            new_executable = "b" * 64
            execution = {
                "mode": "reconcile",
                "run_class": "phase8-cohort-a",
                "release_scope": "partial-portfolio",
                "release_label": "Phase 8 Cohort A",
                "selected_library_ids": selected,
                "excluded_library_ids": excluded,
                "metadata_batch_size": 50,
                "network_task_source_sha256": old_executable,
                "historical_network_request_attempts": {
                    "github-code-search": 0,
                    "sourcegraph": 0,
                },
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
            library = next(
                item for item in config.LIBRARIES
                if item["id"] == "cublas"
            )
            specs = _discovery_specs([library])
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog=library,
                    fingerprints={
                        key: "0" * 64
                        for key in (
                            "discovery",
                            "detector",
                            "citation",
                            "dating",
                            "aggregation",
                            "presentation",
                            "release",
                        )
                    },
                )
                state.create_run(
                    "predecessor",
                    mode="reconcile",
                    plan={
                        **plan.to_dict(),
                        "execution_contract": execution,
                    },
                    budgets=budgets.to_dict(),
                    fingerprints=predecessor_fingerprints,
                    base_release_id="fixture-release",
                    status="running",
                )
                for spec in specs:
                    task_id = state.enqueue_task(
                        "predecessor",
                        "discovery-query",
                        _task_key(spec),
                        library_id="cublas",
                        payload=spec,
                    )
                    _complete_task(
                        state, task_id, _discovery_document(spec)
                    )
                metadata_key, metadata_payload, metadata_result = (
                    _metadata_fixture()
                )
                metadata_task = state.enqueue_task(
                    "predecessor",
                    "github-metadata-batch",
                    metadata_key,
                    payload=metadata_payload,
                )
                _complete_task(
                    state, metadata_task, metadata_result
                )
                state.upsert_repository({
                    "node_id": "R_current",
                    "full_name": "public/example",
                    "visibility": "PUBLIC",
                    "is_fork": False,
                    "is_archived": False,
                    "head_sha": "a" * 40,
                    "metadata": {
                        "explicitly_public": True,
                        "is_private": False,
                        "visibility": "PUBLIC",
                        "node_id": "R_current",
                        "full_name": "public/example",
                        "head_oid": "a" * 40,
                        "disk_usage_kb": 4,
                    },
                })
                scan_task = state.enqueue_task(
                    "predecessor",
                    "scan",
                    "R_current:cublas",
                    repository_id="R_current",
                    library_id="cublas",
                    payload={
                        "node_id": "R_current",
                        "full_name": "public/example",
                        "head_sha": "a" * 40,
                        "library_ids": ["cublas"],
                    },
                )
                _complete_task(
                    state, scan_task, _scan_usage()
                )
                state.abandon_run(
                    "predecessor",
                    reason="content_diagnostic_remediation",
                )
            source_audit = {
                "predecessor_network_task_source_sha256": (
                    old_executable
                ),
                "successor_network_task_source_sha256": (
                    new_executable
                ),
                "per_task_execution_equivalent": True,
                "raw_network_source_changed": True,
                "content_diagnostic_semantics_only": True,
                "remediation_kind": (
                    _CONTENT_DIAGNOSTIC_REMEDIATION_KIND
                ),
                "predecessor_lfs_transfer_bound": (
                    _lfs_transfer_bound_proof()
                ),
            }
            with mock.patch(
                "collector.successor._cohort_successor_source_audit",
                return_value=source_audit,
            ), mock.patch(
                "collector.successor.shutil.disk_usage",
                return_value=mock.Mock(
                    total=2 * 10**15,
                    used=10**12,
                    free=10**15,
                ),
            ):
                report = prepare_phase8_cohort_successor(
                    repo_root=root,
                    state_path=state_path,
                    data_dir=data,
                    predecessor_run_id="predecessor",
                    predecessor_source_ref="fixture",
                    reason="content_diagnostic_remediation",
                    budgets=budgets,
                    recovery_remediation=True,
                    scan_runtime_remediation=True,
                )
            self.assertEqual(len(specs), report["inherited_tasks"])
            self.assertEqual(1, report["inherited_metadata_tasks"])
            self.assertEqual(0, report["pending_tasks"])
            self.assertEqual(1, report["refused_scan_tasks"])
            self.assertEqual(
                "detector_fingerprint_changed",
                report["scan_reuse_refusal_reason"],
            )
            contract = report["fingerprint_audit"][
                "content_diagnostic_contract"
            ]
            self.assertEqual(
                len(active), contract["changed_detector_count"]
            )
            self.assertFalse(contract["old_scan_reuse_allowed"])
            historical = report["historical_scan_usage"]
            self.assertEqual(1, historical["attempt_count"])
            self.assertEqual(1, historical["exact_attempt_count"])
            self.assertEqual(0, historical["conservative_attempt_count"])
            self.assertEqual(
                "scan-attempt-ledger-v1",
                historical["proof_rows"][0]["method"],
            )
            with StateDB(state_path) as state:
                successor_id = report["successor_run_id"]
                successor_plan = json.loads(
                    state.connection.execute(
                        "SELECT plan_json FROM runs WHERE run_id=?",
                        (successor_id,),
                    ).fetchone()[0]
                )
                self.assertEqual(
                    historical,
                    successor_plan["execution_contract"][
                        "historical_scan_usage"
                    ],
                )
                self.assertEqual(
                    historical["contract_sha256"],
                    successor_plan["successor_lineage"][
                        "historical_scan_usage_sha256"
                    ],
                )
                dispatches = successor_plan["cohort_preflight"][
                    "scan_dispatch_attempts"
                ]
                self.assertEqual(1, dispatches["historical_charged"])
                self.assertEqual(1, dispatches["planned_new"])
                self.assertEqual(2, dispatches["combined_upper"])
                self.assertEqual(
                    2,
                    successor_plan["cohort_preflight"][
                        "hard_budget_checks"
                    ]["fetches"]["predicted_upper"],
                )
                self.assertEqual(
                    0,
                    state.connection.execute(
                        """
                        SELECT COUNT(*) FROM scan_attempts
                        WHERE run_id=?
                        """,
                        (successor_id,),
                    ).fetchone()[0],
                )
                stage_counts = {
                    row["stage"]: int(row["count"])
                    for row in state.connection.execute(
                        """
                        SELECT stage, COUNT(*) AS count
                        FROM tasks WHERE run_id=?
                        GROUP BY stage
                        """,
                        (successor_id,),
                    )
                }
                self.assertEqual(
                    {
                        "discovery-query": len(specs),
                        "github-metadata-batch": 1,
                    },
                    stage_counts,
                )
                inherited_stages = {
                    row["stage"]: int(row["count"])
                    for row in state.connection.execute(
                        """
                        SELECT t.stage, COUNT(*) AS count
                        FROM task_inheritance i
                        JOIN tasks t
                          ON t.task_id=i.successor_task_id
                        WHERE i.successor_run_id=?
                        GROUP BY t.stage
                        """,
                        (successor_id,),
                    )
                }
                self.assertEqual(stage_counts, inherited_stages)


if __name__ == "__main__":
    unittest.main()
