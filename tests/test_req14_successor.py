"""Regression tests for audited scope-reduction successor runs."""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from collector import config
from collector.discovery import (
    CoverageCertificate,
    CoverageGap,
    DiscoveryObservation,
    DiscoveryResult,
    github_query_fingerprint,
    query_packs,
    sourcegraph_query_fingerprint,
)
from collector.pipeline import (
    NO_LIVE_V2_RELEASE,
    PipelineError,
    RunBudgets,
    _durable_discovery_request_usage,
    _discovery_result_to_task_result,
    _library_fp_values,
    _metadata_result_to_task_result,
    _network_task_source_sha256,
)
from collector.github_client import (
    GraphQLResolution,
    RepositoryMetadata,
)
from collector.fingerprints import canonical_json, fingerprint
from collector.phase8_control import (
    authorize_phase8_buildozer_retry,
    authorize_phase8_issue_retry,
    authorize_phase8_wall_extension,
)
from collector.phase8_issue_lane import (
    verify_blocked_lfs_inspection_contract,
    verify_notebook_negative_contract,
)
from collector.phase8_source_migration import (
    _SOURCE_RETRY_INCIDENTS,
    _effective_detectors,
    _scan_task_key,
    authorize_phase8_scanner_source_issue_retry,
)
from collector.planner import build_plan, current_fingerprints
from collector.state import StateDB
from collector.successor import (
    _PREFLIGHT_REUSE_REMEDIATION_PROFILE,
    _SCAN_RUNTIME_REMEDIATION_PROFILES,
    _SCAN_RUNTIME_REMEDIATION_REQUIRED_PATHS,
    _cohort_candidate_preflight,
    _cohort_recovery_preflight,
    _assert_cohort_fingerprint_compatibility,
    _derive_certified_cohort,
    _discovery_specs,
    _is_content_diagnostic_candidate,
    _module_import_names,
    _normalized_discovery_usage_digest,
    _task_key,
    _sha256,
    _validate_certified_scan_checkpoint_contract,
    _validated_metadata_task,
    prepare_phase8_cohort_successor,
    prepare_scope_reduction_successor,
    prepare_transport_policy_successor,
)


ROOT = Path(__file__).resolve().parents[1]
PREDECESSOR = "predecessor"
NOW = datetime.datetime(2026, 7, 29, tzinfo=datetime.timezone.utc)


def _complete_task(state, task_id, document):
    leased = state.lease_task_by_id(
        task_id, worker="fixture", lease_seconds=300
    )
    if leased is None:
        raise AssertionError("fixture task was not leaseable")
    state.complete_task(task_id, worker="fixture", result=document)


def _document(
    spec,
    *,
    complete=True,
    terminal=True,
    gaps=(),
    quarantined=False,
    request_count=2,
):
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
    certificate = CoverageCertificate(
        source=spec["source"],
        library_id=spec["library_id"],
        query_fingerprint=spec["query_fingerprint"],
        epoch_started_at=NOW,
        epoch_completed_at=NOW if terminal else None,
        complete=complete,
        terminal=terminal,
        observations_count=0 if quarantined else 1,
        quarantined_count=1 if quarantined else 0,
        gaps=tuple(gaps),
        metrics={"request_count": request_count},
    )
    result = DiscoveryResult(
        observations=() if quarantined else (observation,),
        quarantined_observations=(observation,) if quarantined else (),
        certificate=certificate,
    )
    return _discovery_result_to_task_result(result)


class SuccessorFixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state_path = Path(self.temporary.name) / "collector.sqlite3"
        self.budgets = RunBudgets.reconcile()
        self.plan = build_plan(
            mode="reconcile",
            state_path=self.state_path,
            data_dir=ROOT / "data",
            libraries=config.LIBRARIES,
            weekly_scan_budget=self.budgets.max_scan_repositories,
            max_graphql_points=self.budgets.max_graphql_points,
            min_graphql_remaining=self.budgets.min_graphql_remaining,
        )
        self.current_specs = _discovery_specs(config.LIBRARIES)
        self.current_by_key = {
            _task_key(spec): spec for spec in self.current_specs
        }
        current_fingerprints = self.plan.fingerprints.as_dict()
        self.predecessor_fingerprints = copy.deepcopy(
            current_fingerprints
        )
        for field in ("discovery", "detector", "presentation"):
            self.predecessor_fingerprints["libraries"]["cusparselt"][
                field
            ] = (
                {
                    "discovery": "a",
                    "detector": "b",
                    "presentation": "c",
                }[field]
                * 64
            )
        broad = {
            "library_id": "cusparselt",
            "signal_id": "broad-00",
            "query": '"cusparseLt"',
            "extensions": [],
            "pack_kind": "broad",
            "member_signal_ids": ["broad-00"],
        }
        sg = {
            **broad,
            "source": "sourcegraph",
        }
        sg["query_fingerprint"] = sourcegraph_query_fingerprint(
            type("Pack", (), {
                "library_id": "cusparselt",
                "signal_id": "broad-00",
                "kind": "broad",
                "member_signal_ids": ("broad-00",),
                "anchors": ("cusparseLt",),
                "github_query": '"cusparseLt"',
                "sourcegraph_query": '"cusparseLt"',
                "extensions": (),
            })()
        )
        gh = {
            **broad,
            "source": "github-code-search",
        }
        gh["query_fingerprint"] = github_query_fingerprint(
            type("Pack", (), {
                "library_id": "cusparselt",
                "signal_id": "broad-00",
                "kind": "broad",
                "member_signal_ids": ("broad-00",),
                "anchors": ("cusparseLt",),
                "github_query": '"cusparseLt"',
                "sourcegraph_query": '"cusparseLt"',
                "extensions": (),
            })()
        )
        self.removed_specs = (sg, gh)
        self._seed()

    def cleanup(self):
        self.temporary.cleanup()

    def _seed(self):
        execution = {
            "mode": "reconcile",
            "selected_library_ids": sorted(
                library["id"] for library in config.LIBRARIES
            ),
            "metadata_batch_size": 50,
            "network_task_source_sha256": (
                _network_task_source_sha256()
            ),
        }
        with StateDB(self.state_path) as state:
            for library in config.LIBRARIES:
                state.upsert_library(
                    library["id"],
                    catalog={},
                    fingerprints=_library_fp_values(
                        self.plan, library["id"]
                    ),
                )
            state.create_run(
                PREDECESSOR,
                mode="reconcile",
                plan={
                    **self.plan.to_dict(),
                    "execution_contract": execution,
                },
                budgets=self.budgets.to_dict(),
                fingerprints=self.predecessor_fingerprints,
                base_release_id=NO_LIVE_V2_RELEASE,
                status="running",
            )
            special = {}
            for spec in self.current_specs + list(self.removed_specs):
                key = _task_key(spec)
                special[key] = state.enqueue_task(
                    PREDECESSOR,
                    "discovery-query",
                    key,
                    library_id=spec["library_id"],
                    payload=spec,
                )

            github = next(
                spec
                for spec in self.current_specs
                if spec["source"] == "github-code-search"
                and spec["library_id"] == "cublaslt"
            )
            advisory = next(
                spec
                for spec in self.current_specs
                if spec["source"] == "sourcegraph"
                and spec["library_id"] == "cublaslt"
            )
            nonterminal = next(
                spec
                for spec in self.current_specs
                if spec["source"] == "sourcegraph"
                and spec["library_id"] == "cublas"
            )
            required_quarantine = next(
                spec
                for spec in self.current_specs
                if spec["source"] == "github-code-search"
                and spec["library_id"] == "cublas"
            )
            _complete_task(
                state,
                special[_task_key(github)],
                _document(github, request_count=7),
            )
            _complete_task(
                state,
                special[_task_key(advisory)],
                _document(
                    advisory,
                    complete=False,
                    gaps=(
                        CoverageGap(
                            "server_timeout",
                            "advisory timeout",
                            retryable=True,
                        ),
                    ),
                    request_count=1,
                ),
            )
            _complete_task(
                state,
                special[_task_key(nonterminal)],
                _document(
                    nonterminal,
                    complete=False,
                    terminal=False,
                    request_count=1,
                ),
            )
            _complete_task(
                state,
                special[_task_key(required_quarantine)],
                _document(
                    required_quarantine,
                    quarantined=True,
                    request_count=3,
                ),
            )
            _complete_task(
                state,
                special[_task_key(self.removed_specs[0])],
                _document(self.removed_specs[0]),
            )
            state.abandon_run(
                PREDECESSOR, reason="cusparselt_scope_reduction"
            )


class SuccessorTests(unittest.TestCase):
    def test_certified_scan_checkpoint_contract_is_exact_and_hashed(self):
        certificate = {
            "version": 1,
            "kind": "phase8-exact-scan-checkpoint-compatibility",
            "predecessor_run_id": "20260731T052650Z-cd66b01e",
            "predecessor_source_ref": "4508569",
            "task_count": 37,
            "result_row_count": 237,
            "candidate_postimage_count": 421,
            "analysis_postimage_count": 14,
            "notebook_path_count": 316,
            "eligible_notebook_path_count": 192,
            "eligible_notebook_blob_count": 181,
            "parser_difference_count": 0,
            "task_proofs_sha256": "1" * 64,
            "result_proofs_sha256": "2" * 64,
            "candidate_postimages_sha256": "3" * 64,
            "analysis_postimages_sha256": "4" * 64,
            "notebook_inventory_sha256": "5" * 64,
            "notebook_parser_proofs_sha256": "6" * 64,
            "classifications": {
                "confirmed": 43,
                "rejected": 191,
                "targeted": 3,
            },
            "target_row_count": 237,
            "compatible_selected_pair_count": 113,
        }
        certificate["certificate_sha256"] = _sha256(certificate)
        self.assertEqual(
            certificate,
            _validate_certified_scan_checkpoint_contract(certificate),
        )
        changed = copy.deepcopy(certificate)
        changed["result_row_count"] -= 1
        changed["certificate_sha256"] = _sha256({
            key: value
            for key, value in changed.items()
            if key != "certificate_sha256"
        })
        with self.assertRaisesRegex(PipelineError, "scope changed"):
            _validate_certified_scan_checkpoint_contract(changed)

    def test_content_profile_is_only_the_parser_addition(self):
        with mock.patch(
            "collector.successor._git",
            return_value=b"",
        ):
            self.assertTrue(
                _is_content_diagnostic_candidate(
                    ROOT,
                    "predecessor",
                    ("collector/evidence_content.py",),
                    scan_runtime_remediation=True,
                )
            )
        with mock.patch(
            "collector.successor._git",
            return_value=b"tracked-entry",
        ):
            self.assertFalse(
                _is_content_diagnostic_candidate(
                    ROOT,
                    "predecessor",
                    ("collector/evidence_content.py",),
                    scan_runtime_remediation=True,
                )
            )

    def test_preflight_reuse_profile_is_exact(self):
        self.assertEqual(
            {
                "collector/cli.py": (
                    "_prepare_phase8_cohort_recovery_successor",
                    "build_parser",
                ),
                "collector/successor.py": (
                    "<module>.Assign:11",
                    "<module>.Assign:12",
                    "<module>.Assign:13",
                    "<module>.ImportFrom:9",
                    "_cohort_candidate_preflight",
                    "_cohort_recovery_preflight",
                    "_cohort_successor_source_audit",
                    "prepare_phase8_cohort_successor",
                ),
            },
            _PREFLIGHT_REUSE_REMEDIATION_PROFILE,
        )

    def test_scan_runtime_profiles_are_exact_and_do_not_overlap(self):
        profiles = _SCAN_RUNTIME_REMEDIATION_PROFILES
        self.assertEqual(
            {
                "checkpoint-continuation-and-certified-reuse",
                "clone-integrity-timeout-policy",
                "copied-orbslam-workspace-provenance",
                "generated-evidence-band-exclusion",
                "generated-lfs-evidence-relevance",
                "git-lfs-checkout-and-content-availability",
                "git-root-rename-boundary-and-timeout-classification",
                "strict-notebook-recovery-and-deadline-propagation",
                "worker-deadline-and-notebook-bom",
            },
            set(profiles),
        )
        normalized = [
            tuple(
                sorted(
                    (path, tuple(nodes))
                    for path, nodes in profile.items()
                )
            )
            for profile in profiles.values()
        ]
        self.assertEqual(len(normalized), len(set(normalized)))
        self.assertEqual(
            set(profiles),
            set(_SCAN_RUNTIME_REMEDIATION_REQUIRED_PATHS),
        )
        self.assertEqual(
            {
                "collector/scan.py": (
                    "_rename_predecessors",
                ),
                "collector/scanner_v2.py": (
                    "_scan_error_contract",
                ),
            },
            profiles[
                "git-root-rename-boundary-and-timeout-classification"
            ],
        )
        self.assertEqual(
            {
                "collector/scan.py": (
                    "_has_token_reference",
                    "_scan_repo_once",
                ),
            },
            profiles["generated-evidence-band-exclusion"],
        )
        self.assertEqual(
            {
                "collector/scan.py": (
                    "_has_token_reference",
                    "_is_generated_evidence_path",
                    "_scan_repo_once",
                ),
                "collector/triage.py": (
                    "_eligible",
                    "_is_binary_media_path",
                    "_is_generated_evidence_path",
                    "_own_source",
                    "_tracked_text_inventory",
                ),
            },
            profiles["generated-lfs-evidence-relevance"],
        )
        self.assertEqual(
            {
                "collector/triage.py": (
                    "_embedded_project_roots",
                    "_inside_embedded_project",
                ),
            },
            profiles["copied-orbslam-workspace-provenance"],
        )
        self.assertEqual(
            {
                "collector/scan.py": (
                    "_notebook_source_surfaces",
                ),
                "collector/scanner_v2.py": (
                    "scan_many",
                ),
                "collector/triage.py": (
                    "_notebook_surfaces",
                ),
            },
            profiles["worker-deadline-and-notebook-bom"],
        )
        self.assertEqual(
            {
                "collector/scan.py": (
                    "_verify_clone",
                ),
            },
            profiles["clone-integrity-timeout-policy"],
        )
        self.assertEqual(
            {
                "collector/evidence_content.py": (
                    "_bounded_json_recovery",
                    "_surface_document",
                    "parse_notebook_surfaces",
                ),
                "collector/repo_cache.py": (
                    "RepoCache._materialize_relevant_lfs",
                ),
                "collector/successor.py": (
                    "<module>.Assign:14",
                    "<module>.Assign:15",
                    "_cohort_successor_source_audit",
                    "_is_content_diagnostic_candidate",
                ),
            },
            profiles[
                "strict-notebook-recovery-and-deadline-propagation"
            ],
        )

    def setUp(self):
        self.fixture = SuccessorFixture()
        self.addCleanup(self.fixture.cleanup)

    def _prepare(self):
        return prepare_scope_reduction_successor(
            repo_root=ROOT,
            state_path=self.fixture.state_path,
            data_dir=ROOT / "data",
            predecessor_run_id=PREDECESSOR,
            allowed_library_id="cusparselt",
            reason="cusparselt_targeted_scope_reduction",
            budgets=self.fixture.budgets,
        )

    def test_scope_reduction_reuses_only_certified_exact_tasks(self):
        report = self._prepare()
        self.assertEqual(2, len(report["removed_tasks"]))
        self.assertEqual(
            len(self.fixture.current_specs), report["current_task_count"]
        )
        self.assertEqual(2, report["inherited_tasks"])
        self.assertEqual(
            1, report["refused_completed_tasks"]["invalid_advisory"]
        )
        self.assertEqual(
            1, report["refused_completed_tasks"]["invalid_required"]
        )
        self.assertEqual(
            len(self.fixture.current_specs) - 4,
            report["refused_completed_tasks"]["not_completed"],
        )
        self.assertEqual(
            {"github-code-search": 7, "sourcegraph": 1},
            report["inherited_requests"],
        )
        with StateDB(self.fixture.state_path) as state:
            inherited = list(state.connection.execute(
                """
                SELECT ti.*, t.attempts, t.status
                FROM task_inheritance ti
                JOIN tasks t ON t.task_id=ti.successor_task_id
                WHERE ti.successor_run_id=?
                ORDER BY ti.task_key
                """,
                (report["successor_run_id"],),
            ))
            self.assertEqual(2, len(inherited))
            self.assertTrue(all(row["attempts"] == 0 for row in inherited))
            self.assertTrue(
                all(row["status"] == "complete" for row in inherited)
            )
            coverage_queries = {
                row["query_fp"]
                for row in state.connection.execute(
                    """
                    SELECT query_fp FROM discovery_coverage
                    WHERE run_id=?
                    """,
                    (report["successor_run_id"],),
                )
            }
            removed_fingerprints = {
                spec["query_fingerprint"]
                for spec in self.fixture.removed_specs
            }
            self.assertTrue(
                coverage_queries.isdisjoint(removed_fingerprints)
            )
            diagnostics = state.discovery_publication_diagnostics(
                report["successor_run_id"]
            )
            self.assertGreater(
                diagnostics["sources"]["sourcegraph"][
                    "incomplete_rows"
                ],
                0,
            )

    def test_prepare_is_crash_restart_idempotent(self):
        first = self._prepare()
        second = self._prepare()
        self.assertEqual(
            first["successor_run_id"], second["successor_run_id"]
        )
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        with StateDB(self.fixture.state_path) as state:
            self.assertEqual(
                2,
                state.connection.execute(
                    """
                    SELECT COUNT(*) FROM task_inheritance
                    WHERE successor_run_id=?
                    """,
                    (first["successor_run_id"],),
                ).fetchone()[0],
            )

    def test_scope_expansion_is_refused(self):
        with StateDB(self.fixture.state_path) as state:
            state.connection.execute(
                """
                DELETE FROM tasks
                WHERE run_id=? AND task_key=(
                    SELECT task_key FROM tasks
                    WHERE run_id=? AND library_id='cublaslt'
                    LIMIT 1
                )
                """,
                (PREDECESSOR, PREDECESSOR),
            )
        with self.assertRaisesRegex(
            Exception, "add discovery tasks"
        ):
            self._prepare()

    def test_public_only_state_boundary_rejects_private_documents(self):
        spec = self.fixture.current_specs[0]
        document = _document(spec)
        document["observations"][0]["visibility"] = "private"
        with StateDB(self.fixture.state_path) as state:
            task_id = next(
                row["task_id"]
                for row in state.connection.execute(
                    """
                    SELECT task_id FROM tasks
                    WHERE run_id=? AND status='failed' LIMIT 1
                    """,
                    (PREDECESSOR,),
                )
            )
            state.connection.execute(
                """
                UPDATE tasks SET status='pending', attempts=0,
                    lease_owner=NULL, lease_expires_at=NULL
                WHERE task_id=?
                """,
                (task_id,),
            )
            state.lease_task_by_id(
                task_id, worker="fixture-private", lease_seconds=300
            )
            with self.assertRaisesRegex(ValueError, "non-public"):
                state.complete_task(
                    task_id,
                    worker="fixture-private",
                    result=document,
                )


class TransportSuccessorFixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state_path = Path(self.temporary.name) / "collector.sqlite3"
        self.budgets = RunBudgets.reconcile()
        self.plan = build_plan(
            mode="reconcile",
            state_path=self.state_path,
            data_dir=ROOT / "data",
            libraries=config.LIBRARIES,
            weekly_scan_budget=self.budgets.max_scan_repositories,
            max_graphql_points=self.budgets.max_graphql_points,
            min_graphql_remaining=self.budgets.min_graphql_remaining,
        )
        self.specs = _discovery_specs(config.LIBRARIES)
        self.old_executable = "d" * 64
        self.new_executable = _network_task_source_sha256()
        self.source_audit = {
            "predecessor_source_ref": "old-ref",
            "predecessor_source_commit": "1" * 40,
            "successor_source_commit": "2" * 40,
            "changed_paths": [
                "collector/http_transport.py",
                "collector/pipeline.py",
            ],
            "predecessor_network_task_source_sha256": (
                self.old_executable
            ),
            "successor_network_task_source_sha256": (
                self.new_executable
            ),
            "predecessor_transport_source_sha256": "a" * 64,
            "successor_transport_source_sha256": "b" * 64,
        }
        self._seed()

    def cleanup(self):
        self.temporary.cleanup()

    def _seed(self):
        execution = {
            "mode": "reconcile",
            "selected_library_ids": sorted(
                library["id"] for library in config.LIBRARIES
            ),
            "metadata_batch_size": 50,
            "network_task_source_sha256": self.old_executable,
        }
        with StateDB(self.state_path) as state:
            for library in config.LIBRARIES:
                state.upsert_library(
                    library["id"],
                    catalog={},
                    fingerprints=_library_fp_values(
                        self.plan, library["id"]
                    ),
                )
            state.create_run(
                PREDECESSOR,
                mode="reconcile",
                plan={
                    **self.plan.to_dict(),
                    "execution_contract": execution,
                },
                budgets=self.budgets.to_dict(),
                fingerprints=self.plan.fingerprints.as_dict(),
                base_release_id=NO_LIVE_V2_RELEASE,
                status="running",
            )
            task_ids = {}
            for spec in self.specs:
                task_ids[_task_key(spec)] = state.enqueue_task(
                    PREDECESSOR,
                    "discovery-query",
                    _task_key(spec),
                    library_id=spec["library_id"],
                    payload=spec,
                )
            required = next(
                spec
                for spec in self.specs
                if spec["source"] == "github-code-search"
                and spec["library_id"] == "cublaslt"
            )
            advisory = next(
                spec
                for spec in self.specs
                if spec["source"] == "sourcegraph"
                and spec["library_id"] == "cublaslt"
            )
            invalid_required = next(
                spec
                for spec in self.specs
                if spec["source"] == "github-code-search"
                and spec["library_id"] == "cublas"
            )
            _complete_task(
                state,
                task_ids[_task_key(required)],
                _document(required, request_count=7),
            )
            _complete_task(
                state,
                task_ids[_task_key(advisory)],
                _document(
                    advisory,
                    complete=False,
                    gaps=(
                        CoverageGap(
                            "server_timeout",
                            "advisory timeout",
                            retryable=True,
                        ),
                    ),
                    request_count=1,
                ),
            )
            _complete_task(
                state,
                task_ids[_task_key(invalid_required)],
                _document(
                    invalid_required,
                    quarantined=True,
                    request_count=3,
                ),
            )
            state.abandon_run(
                PREDECESSOR, reason="transport_policy_remediation"
            )


class TransportSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = TransportSuccessorFixture()
        self.addCleanup(self.fixture.cleanup)

    def _prepare(self, source_audit=None):
        with mock.patch(
            "collector.successor._transport_policy_source_audit",
            return_value=source_audit or self.fixture.source_audit,
        ):
            return prepare_transport_policy_successor(
                repo_root=ROOT,
                state_path=self.fixture.state_path,
                data_dir=ROOT / "data",
                predecessor_run_id=PREDECESSOR,
                predecessor_source_ref="old-ref",
                reason="github_secondary_throttle_remediation",
                historical_github_request_attempts=446,
                budgets=self.fixture.budgets,
            )

    def test_exact_tasks_reuse_across_audited_transport_change(self):
        report = self._prepare()
        self.assertEqual(len(self.fixture.specs), report["current_task_count"])
        self.assertEqual(2, report["inherited_tasks"])
        self.assertEqual(
            1, report["refused_completed_tasks"]["invalid_required"]
        )
        self.assertEqual(
            len(self.fixture.specs) - 3,
            report["refused_completed_tasks"]["not_completed"],
        )
        self.assertEqual(
            {"github-code-search": 7, "sourcegraph": 1},
            report["inherited_requests"],
        )
        self.assertEqual(453, report["charged_github_request_attempts"])
        equivalence = report["query_execution_equivalence"]
        self.assertEqual(equivalence["logical_operator"], "OR")
        self.assertEqual(
            equivalence["pack_count"],
            sum(len(query_packs(library)) for library in config.LIBRARIES),
        )
        self.assertGreater(equivalence["multi_member_pack_count"], 0)
        self.assertEqual(
            self.fixture.old_executable,
            report["predecessor_network_task_source_sha256"],
        )
        self.assertEqual(
            self.fixture.new_executable,
            report["successor_network_task_source_sha256"],
        )
        with StateDB(self.fixture.state_path) as state:
            successor_id = report["successor_run_id"]
            lineage = state.connection.execute(
                """
                SELECT compatibility_json FROM run_lineage
                WHERE successor_run_id=?
                """,
                (successor_id,),
            ).fetchone()
            compatibility = json.loads(lineage["compatibility_json"])
            self.assertEqual(
                "transport-policy-remediation",
                compatibility["kind"],
            )
            self.assertEqual(
                self.fixture.old_executable,
                compatibility["predecessor_network_task_source_sha256"],
            )
            self.assertEqual(
                self.fixture.new_executable,
                compatibility["successor_network_task_source_sha256"],
            )
            inherited_hashes = {
                row["network_task_source_sha256"]
                for row in state.connection.execute(
                    """
                    SELECT network_task_source_sha256
                    FROM task_inheritance
                    WHERE successor_run_id=?
                    """,
                    (successor_id,),
                )
            }
            self.assertEqual(
                {self.fixture.old_executable}, inherited_hashes
            )
            run = state.connection.execute(
                "SELECT plan_json FROM runs WHERE run_id=?",
                (successor_id,),
            ).fetchone()
            execution = json.loads(run["plan_json"])[
                "execution_contract"
            ]
            self.assertEqual(
                self.fixture.new_executable,
                execution["network_task_source_sha256"],
            )
            usage = _durable_discovery_request_usage(
                state, successor_id
            )
            self.assertEqual(
                453,
                usage["sources"]["github-code-search"]["charged"],
            )
            self.assertEqual(
                1,
                usage["sources"]["sourcegraph"]["charged"],
            )

    def test_prepare_is_idempotent(self):
        first = self._prepare()
        second = self._prepare()
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(
            first["successor_run_id"], second["successor_run_id"]
        )

    def test_changed_payload_and_source_ref_hash_are_refused(self):
        with StateDB(self.fixture.state_path) as state:
            row = state.connection.execute(
                """
                SELECT task_id, payload_json FROM tasks
                WHERE run_id=? AND stage='discovery-query'
                ORDER BY task_id LIMIT 1
                """,
                (PREDECESSOR,),
            ).fetchone()
            payload = json.loads(row["payload_json"])
            payload["query"] += " changed"
            state.connection.execute(
                "UPDATE tasks SET payload_json=? WHERE task_id=?",
                (json.dumps(payload, sort_keys=True, separators=(",", ":")),
                 row["task_id"]),
            )
        with self.assertRaisesRegex(
            Exception, "canonical task payload"
        ):
            self._prepare()

        fixture = TransportSuccessorFixture()
        self.addCleanup(fixture.cleanup)
        bad_audit = {
            **fixture.source_audit,
            "predecessor_network_task_source_sha256": "e" * 64,
        }
        with mock.patch(
            "collector.successor._transport_policy_source_audit",
            return_value=bad_audit,
        ):
            with self.assertRaisesRegex(
                Exception, "does not reproduce"
            ):
                prepare_transport_policy_successor(
                    repo_root=ROOT,
                    state_path=fixture.state_path,
                    data_dir=ROOT / "data",
                    predecessor_run_id=PREDECESSOR,
                    predecessor_source_ref="old-ref",
                    reason="github_secondary_throttle_remediation",
                    historical_github_request_attempts=446,
                    budgets=fixture.budgets,
                )


class WallExtensionControlTests(unittest.TestCase):
    def _contract(self, network_sha256=None):
        active = sorted(library["id"] for library in config.LIBRARIES)
        return {
            "run_class": "phase8-cohort-a",
            "release_scope": "partial-portfolio",
            "release_label": "Phase 8 Cohort A",
            "selected_library_ids": [active[0]],
            "excluded_library_ids": active[1:],
            "network_task_source_sha256": (
                network_sha256 or "a" * 64
            ),
            "reviewed_slo": {
                "class": "partial_cohort_reconciliation",
                "target_seconds": 24 * 3600,
                "ceiling_seconds": 36 * 3600,
            },
        }

    @staticmethod
    def _source_audit():
        return {
            "predecessor_source_commit": "1" * 40,
            "successor_source_commit": "2" * 40,
            "predecessor_network_task_source_sha256": "a" * 64,
            "successor_network_task_source_sha256": "b" * 64,
            "source_audit_sha256": "c" * 64,
        }

    def test_wall_control_preserves_tasks_and_changes_only_wall(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "collector.sqlite3"
            baseline = RunBudgets.reconcile().to_dict()
            fingerprints = current_fingerprints().as_dict()
            with StateDB(state_path) as state:
                state.create_run(
                    "cohort",
                    mode="reconcile",
                    plan={"execution_contract": self._contract()},
                    budgets=baseline,
                    fingerprints=fingerprints,
                    status="running",
                )
                task_id = state.enqueue_task(
                    "cohort", "scan", "complete-task", payload={}
                )
                state.lease_task_by_id(
                    task_id, worker="fixture", lease_seconds=300
                )
                state.complete_task(
                    task_id, worker="fixture", result={"status": "ok"}
                )
                with mock.patch(
                    "collector.phase8_control._wall_extension_source_audit",
                    return_value=self._source_audit(),
                ):
                    report = authorize_phase8_wall_extension(
                        state=state,
                        repo_root=root,
                        run_id="cohort",
                        predecessor_source_ref="predecessor",
                        extended_limit_seconds=96 * 3600,
                        reason="phase8_owner_wall_extension",
                    )
                row = state.connection.execute(
                    "SELECT plan_json, budgets_json FROM runs WHERE run_id='cohort'"
                ).fetchone()
                task = state.connection.execute(
                    "SELECT status, attempts FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()
                stage = state.connection.execute(
                    "SELECT checkpoint_json FROM stages "
                    "WHERE run_id='cohort' AND stage='wall_extension'"
                ).fetchone()
            updated_budgets = json.loads(row["budgets_json"])
            self.assertEqual(96 * 3600, updated_budgets["max_wall_seconds"])
            for key, value in baseline.items():
                if key != "max_wall_seconds":
                    self.assertEqual(value, updated_budgets[key])
            contract = json.loads(row["plan_json"])["execution_contract"]
            self.assertEqual("b" * 64, contract["network_task_source_sha256"])
            self.assertEqual("complete", task["status"])
            self.assertEqual(1, task["attempts"])
            self.assertEqual(1, report["completed_scan_tasks_preserved"])
            checkpoint = json.loads(stage["checkpoint_json"])
            self.assertEqual(0, checkpoint["reset_scan_tasks"])
            self.assertEqual(0, checkpoint["other_budget_changes"])

    def test_wall_control_migrates_source_at_same_extended_ceiling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "collector.sqlite3"
            baseline = RunBudgets.reconcile().to_dict()
            fingerprints = current_fingerprints().as_dict()
            with StateDB(state_path) as state:
                state.create_run(
                    "cohort",
                    mode="reconcile",
                    plan={"execution_contract": self._contract()},
                    budgets=baseline,
                    fingerprints=fingerprints,
                    status="running",
                )
                first_audit = self._source_audit()
                with mock.patch(
                    "collector.phase8_control._wall_extension_source_audit",
                    return_value=first_audit,
                ):
                    authorize_phase8_wall_extension(
                        state=state,
                        repo_root=root,
                        run_id="cohort",
                        predecessor_source_ref="first",
                        extended_limit_seconds=96 * 3600,
                        reason="phase8_owner_wall_extension",
                    )
                second_audit = {
                    **first_audit,
                    "predecessor_source_commit": "2" * 40,
                    "successor_source_commit": "3" * 40,
                    "predecessor_network_task_source_sha256": "b" * 64,
                    "successor_network_task_source_sha256": "d" * 64,
                    "source_audit_sha256": "e" * 64,
                }
                with mock.patch(
                    "collector.phase8_control._wall_extension_source_audit",
                    return_value=second_audit,
                ):
                    report = authorize_phase8_wall_extension(
                        state=state,
                        repo_root=root,
                        run_id="cohort",
                        predecessor_source_ref="second",
                        extended_limit_seconds=96 * 3600,
                        reason="phase8_checkpoint_recovery_migration",
                    )
                row = state.connection.execute(
                    "SELECT plan_json,budgets_json FROM runs WHERE run_id='cohort'"
                ).fetchone()
            updated = json.loads(row["budgets_json"])
            contract = json.loads(row["plan_json"])["execution_contract"]
            self.assertEqual(96 * 3600, updated["max_wall_seconds"])
            self.assertEqual("d" * 64, contract["network_task_source_sha256"])
            self.assertEqual(0, report["reset_scan_tasks"])
            self.assertEqual(0, report["other_budget_changes"])

    def test_wall_control_refuses_any_other_budget_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "collector.sqlite3"
            budgets = RunBudgets.reconcile().to_dict()
            budgets["max_fetches"] += 1
            with StateDB(state_path) as state:
                state.create_run(
                    "cohort",
                    mode="reconcile",
                    plan={"execution_contract": self._contract()},
                    budgets=budgets,
                    fingerprints=current_fingerprints().as_dict(),
                    status="running",
                )
                with self.assertRaisesRegex(
                    PipelineError, "another changed hard budget"
                ):
                    authorize_phase8_wall_extension(
                        state=state,
                        repo_root=root,
                        run_id="cohort",
                        predecessor_source_ref="predecessor",
                        extended_limit_seconds=96 * 3600,
                        reason="phase8_owner_wall_extension",
                    )

    def test_approved_buildozer_filter_migrates_and_retries_only_incident(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "collector.sqlite3"
            current = current_fingerprints().as_dict()
            prior = copy.deepcopy(current)
            prior["filters"]["shared"] = "f" * 64
            def effective_detector(document, library_id):
                filter_values = {
                    "shared": document["filters"]["shared"]
                }
                if library_id == "nvpl":
                    filter_values["nvpl"] = document["filters"]["nvpl"]
                return fingerprint(
                    "library:%s:effective-detector" % library_id,
                    {
                        "detector": document["libraries"][library_id][
                            "detector"
                        ],
                        "filters": filter_values,
                    },
                )

            def scan_task_key(repository_id, head_sha, library_ids, document):
                return fingerprint(
                    "scan-task-v2",
                    {
                        "repository_node_id": repository_id,
                        "head_sha": head_sha,
                        "candidate_library_ids": sorted(library_ids),
                        "analysis_only": False,
                        "ai_fingerprint": None,
                        "detector_fingerprints": {
                            library_id: effective_detector(
                                document, library_id
                            )
                            for library_id in sorted(library_ids)
                        },
                    },
                )
            network_sha = _network_task_source_sha256()
            source_proof = {
                "version": 1,
                "directory_segment": ".buildozer",
                "policy": "exact-generated-directory-monotonic-exclusion",
            }
            source_audit = {
                **self._source_audit(),
                "successor_network_task_source_sha256": network_sha,
                "approved_filter_source_proof": source_proof,
            }
            certified_raw = {"fixture": True}
            certified_stub = {
                "certificate_sha256": "c" * 64,
                "target_row_count": 1,
            }
            with StateDB(state_path) as state:
                execution_contract = self._contract()
                execution_contract["certified_scan_checkpoint"] = (
                    certified_raw
                )
                state.create_run(
                    "cohort",
                    mode="reconcile",
                    plan={
                        "fingerprints": prior,
                        "execution_contract": execution_contract,
                    },
                    budgets=RunBudgets.reconcile().to_dict(),
                    fingerprints=prior,
                    status="running",
                )
                state.upsert_repository({
                    "node_id": "R_shoot",
                    "full_name": "Silian1234/shootAnalyzer",
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": "a" * 40,
                    "metadata": {},
                })
                incident_id = self._failed_attempt(
                    state,
                    task_key=scan_task_key(
                        "R_shoot", "a" * 40, ["cublas"], prior
                    ),
                    repository_id="R_shoot",
                    full_name="Silian1234/shootAnalyzer",
                    error_code="detector_error",
                    error_detail="[Errno 20] Not a directory: '[local-path]'",
                    retryable=False,
                )
                state.upsert_repository({
                    "node_id": "R_complete",
                    "full_name": "public/complete",
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": "b" * 40,
                    "metadata": {},
                })
                complete_id = state.enqueue_task(
                    "cohort",
                    "scan",
                    scan_task_key(
                        "R_complete", "b" * 40, ["cublas"], prior
                    ),
                    repository_id="R_complete",
                    payload={
                        "full_name": "public/complete",
                        "head_sha": "b" * 40,
                        "libraries": ["cublas"],
                    },
                )
                state.lease_task_by_id(
                    complete_id, worker="fixture", lease_seconds=300
                )
                complete_result = {
                    "status": "clean_reject",
                    "seconds": 1.0,
                    "current_tree_triage_seconds": 0.5,
                    "history_dating_seconds": 0.0,
                    "analysis_seconds": 0.0,
                    "git_subprocess_count": 1,
                    "network_clone_count": 0,
                    "network_fetch_count": 0,
                    "network_materialized_bytes": 0,
                }
                state.record_scan_attempt_result(
                    complete_id,
                    worker="fixture",
                    status="complete",
                    retryable=False,
                    error_code=None,
                    result=complete_result,
                )
                state.complete_task(
                    complete_id,
                    worker="fixture",
                    result=complete_result,
                )
                state.upsert_library(
                    "cublas",
                    catalog={},
                    fingerprints={
                        **prior["libraries"]["cublas"],
                        "detector": effective_detector(prior, "cublas"),
                        "dating": prior["dating"],
                        "aggregation": prior["aggregation"],
                    },
                )
                state.record_scan_result(
                    repository_id="R_complete",
                    library_id="cublas",
                    head_sha="b" * 40,
                    detector_fp=effective_detector(prior, "cublas"),
                    classification="rejected",
                    status="clean",
                    evidence={},
                )
                state.upsert_repository({
                    "node_id": "R_checkpoint",
                    "full_name": "public/checkpoint",
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": "d" * 40,
                    "metadata": {},
                })
                checkpoint_result_id = state.record_scan_result(
                    repository_id="R_checkpoint",
                    library_id="cublas",
                    head_sha="d" * 40,
                    detector_fp=effective_detector(prior, "cublas"),
                    classification="confirmed",
                    status="clean",
                    evidence={"classification": "confirmed"},
                )
                checkpoint_rows = [{
                    "successor_run_id": "cohort",
                    "predecessor_task_id": 7,
                    "source_scan_result_id": 8,
                    "target_scan_result_id": checkpoint_result_id,
                    "source_detector_fp": "e" * 64,
                    "target_detector_fp": effective_detector(
                        prior, "cublas"
                    ),
                    "source_row_sha256": "f" * 64,
                    "compatibility_sha256": "c" * 64,
                }]
                state.update_stage(
                    "cohort",
                    "scan_checkpoint_reuse",
                    status="complete",
                    checkpoint={
                        "row_count": 1,
                        "provenance_sha256": hashlib.sha256(
                            canonical_json(checkpoint_rows).encode("utf-8")
                        ).hexdigest(),
                        "rows": checkpoint_rows,
                    },
                )
                tree = (
                    ".buildozer/android/platform/build/python-installs/python",
                    ".buildozer/android/platform/build/python-installs/Python/os.py",
                )
                with (
                    mock.patch(
                        "collector.phase8_control._wall_extension_source_audit",
                        return_value=source_audit,
                    ),
                    mock.patch(
                        "collector.phase8_control._git_tree_paths",
                        return_value=tree,
                    ),
                    mock.patch(
                        "collector.phase8_control."
                        "_validate_certified_scan_checkpoint_contract",
                        return_value=certified_stub,
                    ),
                ):
                    extension = authorize_phase8_wall_extension(
                        state=state,
                        repo_root=root,
                        run_id="cohort",
                        predecessor_source_ref="predecessor",
                        extended_limit_seconds=96 * 3600,
                        reason="phase8_owner_wall_extension",
                    )
                retry = authorize_phase8_buildozer_retry(
                    state=state,
                    run_id="cohort",
                    reason="phase8_approved_buildozer_exclusion",
                )
                resumable = state.connection.execute(
                    """
                    SELECT plan_json,budgets_json,fingerprints_json,
                           base_release_id FROM runs WHERE run_id='cohort'
                    """
                ).fetchone()
                state.finish_run("cohort", status="failed")
                self.assertEqual(
                    state.resume_compatible_run(
                        mode="reconcile",
                        budgets=json.loads(resumable["budgets_json"]),
                        fingerprints=json.loads(
                            resumable["fingerprints_json"]
                        ),
                        base_release_id=resumable["base_release_id"],
                        execution_contract=json.loads(
                            resumable["plan_json"]
                        )["execution_contract"],
                    ),
                    "cohort",
                )
                rows = {
                    row["task_id"]: row
                    for row in state.connection.execute(
                        "SELECT task_id,status,attempts,max_attempts "
                        "FROM tasks WHERE run_id='cohort'"
                    )
                }
                run = state.connection.execute(
                    "SELECT plan_json,fingerprints_json FROM runs "
                    "WHERE run_id='cohort'"
                ).fetchone()
                state.lease_task_by_id(
                    incident_id, worker="retry", lease_seconds=300
                )
                recovered = {
                    "status": "clean_reject",
                    "seconds": 1.0,
                    "current_tree_triage_seconds": 0.5,
                    "history_dating_seconds": 0.0,
                    "analysis_seconds": 0.0,
                    "git_subprocess_count": 1,
                    "network_clone_count": 0,
                    "network_fetch_count": 0,
                    "network_materialized_bytes": 0,
                }
                state.record_scan_attempt_result(
                    incident_id,
                    worker="retry",
                    status="complete",
                    retryable=False,
                    error_code=None,
                    result=recovered,
                )
                state.complete_task(
                    incident_id, worker="retry", result=recovered
                )
                with mock.patch(
                    "collector.successor."
                    "_validate_certified_scan_checkpoint_contract",
                    return_value=certified_stub,
                ):
                    state.assert_run_publishable("cohort")
            self.assertIsNotNone(extension["filter_extension"])
            self.assertEqual(1, retry["reset_task_count"])
            self.assertEqual("pending", rows[incident_id]["status"])
            self.assertEqual(2, rows[incident_id]["max_attempts"])
            self.assertEqual("complete", rows[complete_id]["status"])
            self.assertEqual(1, rows[complete_id]["attempts"])
            with StateDB(state_path) as state:
                migrated = state.connection.execute(
                    """
                    SELECT classification,status FROM scan_results
                    WHERE repository_id='R_complete' AND library_id='cublas'
                      AND head_sha=? AND detector_fp=?
                    """,
                    (
                        "b" * 40,
                        effective_detector(current, "cublas"),
                    ),
                ).fetchone()
                migrated_checkpoint = state.connection.execute(
                    """
                    SELECT classification,status FROM scan_results
                    WHERE repository_id='R_checkpoint'
                      AND library_id='cublas' AND head_sha=?
                      AND detector_fp=?
                    """,
                    (
                        "d" * 40,
                        effective_detector(current, "cublas"),
                    ),
                ).fetchone()
                task_keys = {
                    row["task_id"]: row["task_key"]
                    for row in state.connection.execute(
                        "SELECT task_id,task_key FROM tasks"
                    )
                }
            self.assertEqual(("rejected", "clean"), tuple(migrated))
            self.assertEqual(
                ("confirmed", "clean"), tuple(migrated_checkpoint)
            )
            self.assertEqual(
                1,
                extension["filter_extension"][
                    "certified_checkpoint_scan_result_count"
                ],
            )
            self.assertEqual(
                scan_task_key("R_shoot", "a" * 40, ["cublas"], current),
                task_keys[incident_id],
            )
            self.assertEqual(
                scan_task_key("R_complete", "b" * 40, ["cublas"], current),
                task_keys[complete_id],
            )
            self.assertEqual(current, json.loads(run["fingerprints_json"]))
            execution = json.loads(run["plan_json"])["execution_contract"]
            self.assertEqual(
                "Silian1234/shootAnalyzer",
                execution["filter_extension"]["incident_full_name"],
            )

    @staticmethod
    def _failed_attempt(
        state,
        *,
        task_key,
        repository_id,
        full_name,
        error_code,
        error_detail,
        retryable,
        head_sha="a" * 40,
    ):
        task_id = state.enqueue_task(
            "cohort",
            "scan",
            task_key,
            repository_id=repository_id,
            payload={
                "full_name": full_name,
                "head_sha": head_sha,
                "libraries": ["cublas"],
            },
            max_attempts=1,
        )
        worker = "fixture"
        state.lease_task_by_id(
            task_id, worker=worker, lease_seconds=300
        )
        result = {
            "version": 1,
            "kind": "scan-failure",
            "status": "error",
            "head_sha": head_sha,
            "seconds": 1.0,
            "current_tree_triage_seconds": 0.5,
            "history_dating_seconds": 0.0,
            "analysis_seconds": 0.0,
            "git_subprocess_count": 1,
            "network_clone_count": 0,
            "network_fetch_count": 0,
            "network_materialized_bytes": 0,
            "error_code": error_code,
            "retryable": retryable,
            "error": error_detail,
        }
        state.record_scan_attempt_result(
            task_id,
            worker=worker,
            status="failed",
            retryable=retryable,
            error_code=error_code,
            result=result,
        )
        state.fail_task(
            task_id,
            worker=worker,
            error_code=error_code,
            result=result,
            retry=retryable,
        )
        return task_id

    def test_issue_retry_is_selective_accounted_and_preserves_completions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "collector.sqlite3"
            network_sha = _network_task_source_sha256()
            with StateDB(state_path) as state:
                state.create_run(
                    "cohort",
                    mode="reconcile",
                    plan={
                        "execution_contract": self._contract(network_sha)
                    },
                    budgets=RunBudgets.reconcile().to_dict(),
                    fingerprints=current_fingerprints().as_dict(),
                    status="running",
                )
                for index, name in enumerate((
                    "public/timeout",
                    "public/notebook",
                    "public/missing-object",
                    "public/complete",
                )):
                    state.upsert_repository({
                        "node_id": "R_%d" % index,
                        "full_name": name,
                        "visibility": "public",
                        "is_fork": False,
                        "is_archived": False,
                        "default_branch": "main",
                        "head_sha": "a" * 40,
                        "metadata": {},
                    })
                timeout_id = self._failed_attempt(
                    state,
                    task_key="timeout",
                    repository_id="R_0",
                    full_name="public/timeout",
                    error_code="repository_timeout",
                    error_detail="repository wall deadline exhausted",
                    retryable=True,
                )
                notebook_id = self._failed_attempt(
                    state,
                    task_key="notebook",
                    repository_id="R_1",
                    full_name="public/notebook",
                    error_code="invalid_notebook",
                    error_detail="tracked notebook is invalid JSON",
                    retryable=False,
                )
                missing_id = self._failed_attempt(
                    state,
                    task_key="missing-object",
                    repository_id="R_2",
                    full_name="public/missing-object",
                    error_code="detector_error",
                    error_detail=(
                        "current-tree object is unavailable after hydration"
                    ),
                    retryable=False,
                )
                complete_id = state.enqueue_task(
                    "cohort",
                    "scan",
                    "complete",
                    repository_id="R_3",
                    payload={
                        "full_name": "public/complete",
                        "head_sha": "a" * 40,
                        "libraries": ["cublas"],
                    },
                )
                state.lease_task_by_id(
                    complete_id, worker="fixture", lease_seconds=300
                )
                complete_result = {
                    "status": "clean_reject",
                    "seconds": 1.0,
                    "current_tree_triage_seconds": 0.5,
                    "history_dating_seconds": 0.0,
                    "analysis_seconds": 0.0,
                    "git_subprocess_count": 1,
                    "network_clone_count": 0,
                    "network_fetch_count": 0,
                    "network_materialized_bytes": 0,
                }
                state.record_scan_attempt_result(
                    complete_id,
                    worker="fixture",
                    status="complete",
                    retryable=False,
                    error_code=None,
                    result=complete_result,
                )
                state.complete_task(
                    complete_id,
                    worker="fixture",
                    result=complete_result,
                )
                report = authorize_phase8_issue_retry(
                    state=state,
                    run_id="cohort",
                    reason="phase8_typed_transient_retry",
                )
                rows = {
                    row["task_id"]: row
                    for row in state.connection.execute(
                        "SELECT task_id,status,attempts,max_attempts "
                        "FROM tasks WHERE run_id='cohort'"
                    ).fetchall()
                }
            self.assertEqual(2, report["reset_task_count"])
            self.assertEqual("pending", rows[timeout_id]["status"])
            self.assertEqual(2, rows[timeout_id]["max_attempts"])
            self.assertEqual("pending", rows[missing_id]["status"])
            self.assertEqual("failed", rows[notebook_id]["status"])
            self.assertEqual("complete", rows[complete_id]["status"])
            self.assertEqual(1, rows[complete_id]["attempts"])

    def _scanner_source_retry_fixture(
        self, root, *, corrupt_detail=False, stale_coordinator=False
    ):
        state_path = root / "collector.sqlite3"
        current = current_fingerprints().as_dict()
        detectors = _effective_detectors(current)
        migration = {
            "version": 1,
            "successor_source_commit": "a" * 40,
            "task_universe_count": 6 if stale_coordinator else 5,
            "completed_scan_tasks_certified": 1,
            "completed_results_with_virtual_documents_evidence": 0,
        }
        migration["contract_sha256"] = _sha256(migration)
        contract = {
            **self._contract(_network_task_source_sha256()),
            "metadata_batch_size": 50,
            "scanner_source_migration": migration,
        }
        with StateDB(state_path) as state:
            state.create_run(
                "cohort",
                mode="reconcile",
                plan={"execution_contract": contract},
                budgets={
                    **RunBudgets.reconcile().to_dict(),
                    "max_wall_seconds": 168 * 3600,
                },
                fingerprints=current,
                status="running",
            )
            task_ids = []
            for index, incident in enumerate(_SOURCE_RETRY_INCIDENTS):
                repository_id = "R_source_%d" % index
                state.upsert_repository({
                    "node_id": repository_id,
                    "full_name": incident["full_name"],
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": incident["head_sha"],
                    "metadata": {},
                })
                payload = {
                    "full_name": incident["full_name"],
                    "head_sha": incident["head_sha"],
                    "libraries": list(incident["libraries"]),
                }
                task_key = _scan_task_key(
                    {"repository_id": repository_id},
                    payload,
                    detectors,
                    current,
                )
                task_id = state.enqueue_task(
                    "cohort",
                    "scan",
                    task_key,
                    repository_id=repository_id,
                    payload=payload,
                    max_attempts=incident["max_attempts"],
                )
                task_ids.append(task_id)
                for attempt in range(incident["attempts"]):
                    worker = "fixture-%d-%d" % (index, attempt)
                    state.lease_task_by_id(
                        task_id, worker=worker, lease_seconds=300
                    )
                    detail = incident["error_detail"]
                    if corrupt_detail and index == 0:
                        detail += " changed"
                    result = {
                        "version": 1,
                        "kind": "scan-failure",
                        "status": "error",
                        "head_sha": incident["head_sha"],
                        "seconds": 1.0,
                        "current_tree_triage_seconds": 0.5,
                        "history_dating_seconds": 0.0,
                        "analysis_seconds": 0.0,
                        "git_subprocess_count": 1,
                        "network_clone_count": 0,
                        "network_fetch_count": 0,
                        "network_materialized_bytes": 0,
                        "error_code": incident["attempt_error_code"],
                        "retryable": incident["retryable"],
                        "error": detail,
                    }
                    state.record_scan_attempt_result(
                        task_id,
                        worker=worker,
                        status="failed",
                        retryable=incident["retryable"],
                        error_code=incident["attempt_error_code"],
                        result=result,
                    )
                    state.fail_task(
                        task_id,
                        worker=worker,
                        error_code=incident["task_error_code"],
                        result=result,
                        retry=incident["retryable"],
                    )
            state.upsert_repository({
                "node_id": "R_complete",
                "full_name": "public/complete",
                "visibility": "public",
                "is_fork": False,
                "is_archived": False,
                "default_branch": "main",
                "head_sha": "b" * 40,
                "metadata": {},
            })
            complete_id = state.enqueue_task(
                "cohort",
                "scan",
                "complete",
                repository_id="R_complete",
                payload={},
            )
            state.lease_task_by_id(
                complete_id, worker="fixture-complete", lease_seconds=300
            )
            complete_result = {
                "status": "clean_reject",
                "seconds": 1.0,
                "current_tree_triage_seconds": 0.5,
                "history_dating_seconds": 0.0,
                "analysis_seconds": 0.0,
                "git_subprocess_count": 1,
                "network_clone_count": 0,
                "network_fetch_count": 0,
                "network_materialized_bytes": 0,
            }
            state.record_scan_attempt_result(
                complete_id,
                worker="fixture-complete",
                status="complete",
                retryable=False,
                error_code=None,
                result=complete_result,
            )
            state.complete_task(
                complete_id,
                worker="fixture-complete",
                result=complete_result,
            )
            state.update_stage(
                "cohort",
                "phase8_scanner_source_migration",
                status="complete",
                checkpoint={"migration": migration},
            )
            stale_id = None
            if stale_coordinator:
                incident = {
                    "repository_id": "R_stale",
                    "full_name": "DeNA/DeClang",
                    "head_sha": (
                        "62389ff192c43e418ece322a4bcd7fc186d17f99"
                    ),
                    "libraries": ["cusparse", "cusparselt", "cutensor"],
                }
                state.upsert_repository({
                    "node_id": incident["repository_id"],
                    "full_name": incident["full_name"],
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": incident["head_sha"],
                    "metadata": {},
                })
                payload = {
                    "full_name": incident["full_name"],
                    "head_sha": incident["head_sha"],
                    "libraries": incident["libraries"],
                }
                stale_id = state.enqueue_task(
                    "cohort",
                    "scan",
                    _scan_task_key(
                        {"repository_id": incident["repository_id"]},
                        payload,
                        detectors,
                        current,
                    ),
                    repository_id=incident["repository_id"],
                    payload=payload,
                    max_attempts=2,
                )
                state.lease_task_by_id(
                    stale_id, worker="stale-1", lease_seconds=300
                )
                timeout = {
                    "version": 1,
                    "kind": "scan-failure",
                    "status": "error",
                    "head_sha": incident["head_sha"],
                    "seconds": 1.0,
                    "current_tree_triage_seconds": 1.0,
                    "history_dating_seconds": 0.0,
                    "analysis_seconds": 0.0,
                    "git_subprocess_count": 1,
                    "network_clone_count": 0,
                    "network_fetch_count": 0,
                    "network_materialized_bytes": 0,
                    "error_code": "repository_timeout",
                    "retryable": True,
                    "error": "repository wall deadline exhausted",
                }
                state.record_scan_attempt_result(
                    stale_id,
                    worker="stale-1",
                    status="failed",
                    retryable=True,
                    error_code="repository_timeout",
                    result=timeout,
                )
                state.fail_task(
                    stale_id,
                    worker="stale-1",
                    error_code="repository_timeout",
                    result=timeout,
                    retry=True,
                )
                state.lease_task_by_id(
                    stale_id, worker="stale-2", lease_seconds=300
                )
            state.finish_run("cohort", status="failed")
        return state_path, contract, task_ids, complete_id, stale_id

    def test_scanner_source_retry_is_exact_and_resume_stable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, contract, task_ids, complete_id, stale_id = (
                self._scanner_source_retry_fixture(
                    root, stale_coordinator=True
                )
            )
            source_audit = {
                "version": 1,
                "scanner_migration_source_commit": "a" * 40,
                "retry_control_source_commit": "b" * 40,
                "changed_control_paths": ["collector/state.py"],
                "source_audit_sha256": "c" * 64,
            }
            with StateDB(state_path) as state, mock.patch(
                "collector.phase8_source_migration._TASK_UNIVERSE", 6
            ), mock.patch(
                "collector.phase8_source_migration."
                "_validate_reviewed_execution_contract",
                return_value=contract,
            ), mock.patch(
                "collector.phase8_source_migration."
                "_source_retry_control_audit",
                return_value=source_audit,
            ), mock.patch(
                "collector.phase8_source_migration."
                "_migrate_prior_issue_retry_certificates",
                return_value={
                    "version": 1,
                    "scanner_migration_contract_sha256": "d" * 64,
                    "migrated_certificates": {
                        "phase8_buildozer_issue_retry": 1,
                        "phase8_issue_retry": 17,
                    },
                    "migrated_task_count": 18,
                },
            ):
                report = authorize_phase8_scanner_source_issue_retry(
                    state=state,
                    repo_root=root,
                    run_id="cohort",
                    reason="phase8_audited_scanner_source_issue_retry",
                )
                rows = {
                    row["task_id"]: row
                    for row in state.connection.execute(
                        "SELECT * FROM tasks WHERE run_id='cohort'"
                    )
                }
                dispositions = {
                    task_id: state._scan_task_recovery_disposition(
                        rows[task_id], allow_unknown_retry=True
                    )
                    for task_id in task_ids
                }
            self.assertEqual(4, report["reset_task_count"])
            self.assertEqual(6, report["task_universe_count"])
            self.assertEqual(
                1, report["stale_coordinator_attempts_recovered"]
            )
            self.assertEqual(
                18, report["prior_issue_retry_task_keys_migrated"]
            )
            for task_id, incident in zip(
                task_ids, _SOURCE_RETRY_INCIDENTS, strict=True
            ):
                self.assertEqual("pending", rows[task_id]["status"])
                self.assertEqual(
                    incident["attempts"] + 1,
                    rows[task_id]["max_attempts"],
                )
                self.assertEqual(
                    (
                        "pending",
                        "issue_retry:audited_scanner_source_migration",
                    ),
                    dispositions[task_id],
                )
            self.assertEqual("complete", rows[complete_id]["status"])
            self.assertEqual(1, rows[complete_id]["attempts"])
            self.assertEqual("failed", rows[stale_id]["status"])
            self.assertEqual(
                "resume_scan_usage_unknown", rows[stale_id]["error_code"]
            )

    def test_scanner_source_retry_rejects_changed_incident_detail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path, contract, task_ids, _complete_id, _stale_id = (
                self._scanner_source_retry_fixture(
                    root, corrupt_detail=True
                )
            )
            with StateDB(state_path) as state, mock.patch(
                "collector.phase8_source_migration._TASK_UNIVERSE", 5
            ), mock.patch(
                "collector.phase8_source_migration."
                "_validate_reviewed_execution_contract",
                return_value=contract,
            ), mock.patch(
                "collector.phase8_source_migration."
                "_source_retry_control_audit",
                return_value={"source_audit_sha256": "c" * 64},
            ), mock.patch(
                "collector.phase8_source_migration."
                "_migrate_prior_issue_retry_certificates",
                return_value={"migrated_task_count": 18},
            ):
                with self.assertRaisesRegex(
                    PipelineError, "incident proof changed"
                ):
                    authorize_phase8_scanner_source_issue_retry(
                        state=state,
                        repo_root=root,
                        run_id="cohort",
                        reason="phase8_audited_scanner_source_issue_retry",
                    )
                statuses = {
                    row["task_id"]: row["status"]
                    for row in state.connection.execute(
                        "SELECT task_id,status FROM tasks"
                    )
                }
            self.assertTrue(
                all(statuses[task_id] == "failed" for task_id in task_ids)
            )

    def test_notebook_proof_derives_new_exact_incident(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "source"
            checkout.mkdir()
            subprocess.run(
                ["git", "init", "-q"], cwd=checkout, check=True
            )
            (checkout / "bad.ipynb").write_bytes(
                b'{"cells": [ malformed but token-negative'
            )
            subprocess.run(
                ["git", "add", "bad.ipynb"], cwd=checkout, check=True
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.com", "commit", "-qm",
                    "fixture",
                ],
                cwd=checkout,
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=checkout,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            full_name = "public/notebook-proof"
            cache_root = root / "cache"
            bare = cache_root / "repos" / (
                hashlib.sha256(full_name.casefold().encode()).hexdigest()
                + ".git"
            )
            bare.parent.mkdir(parents=True)
            subprocess.run(
                ["git", "clone", "-q", "--bare", str(checkout), str(bare)],
                check=True,
            )
            state_path = root / "collector.sqlite3"
            with StateDB(state_path) as state:
                state.create_run(
                    "cohort", mode="reconcile", status="running"
                )
                state.upsert_repository({
                    "node_id": "R_notebook_proof",
                    "full_name": full_name,
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": head,
                    "metadata": {},
                })
                self._failed_attempt(
                    state,
                    task_key="notebook-proof",
                    repository_id="R_notebook_proof",
                    full_name=full_name,
                    error_code="invalid_notebook",
                    error_detail=(
                        "tracked notebook is invalid JSON; scan is "
                        "incomplete: bad.ipynb"
                    ),
                    retryable=False,
                    head_sha=head,
                )
                proof, blobs = verify_notebook_negative_contract(
                    state=state,
                    cache_root=cache_root,
                    run_id="cohort",
                )
            self.assertEqual(1, len(proof["proofs"]))
            self.assertEqual([], proof["proofs"][0]["retention_token_hits"])
            self.assertEqual(1, len(blobs))

    def test_blocked_lfs_proof_derives_exact_nonpointer_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "source"
            checkout.mkdir()
            subprocess.run(
                ["git", "init", "-q"], cwd=checkout, check=True
            )
            blocked_path = "src/blocked.py"
            source = checkout / blocked_path
            source.parent.mkdir(parents=True)
            source.write_bytes(b"print('ordinary source')\n")
            subprocess.run(
                ["git", "add", blocked_path], cwd=checkout, check=True
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.com", "commit", "-qm",
                    "fixture",
                ],
                cwd=checkout,
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=checkout,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            full_name = "public/blocked-lfs"
            cache_root = root / "cache"
            bare = cache_root / "repos" / (
                hashlib.sha256(full_name.casefold().encode()).hexdigest()
                + ".git"
            )
            bare.parent.mkdir(parents=True)
            subprocess.run(
                ["git", "clone", "-q", "--bare", str(checkout), str(bare)],
                check=True,
            )
            state_path = root / "collector.sqlite3"
            with StateDB(state_path) as state:
                state.create_run(
                    "cohort", mode="reconcile", status="running"
                )
                state.upsert_repository({
                    "node_id": "R_blocked_lfs",
                    "full_name": full_name,
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": head,
                    "metadata": {},
                })
                task_id = self._failed_attempt(
                    state,
                    task_key="blocked-lfs",
                    repository_id="R_blocked_lfs",
                    full_name=full_name,
                    error_code="detector_error",
                    error_detail=(
                        "could not inspect detector-relevant LFS path: "
                        + blocked_path
                        + " (errno=1)"
                    ),
                    retryable=False,
                    head_sha=head,
                )
                proof, blobs = verify_blocked_lfs_inspection_contract(
                    state=state,
                    cache_root=cache_root,
                    run_id="cohort",
                )
            self.assertEqual(task_id, proof["proofs"][0]["task_id"])
            self.assertFalse(proof["proofs"][0]["lfs_pointer"])
            self.assertEqual("exact-local-git-blob", proof["proofs"][0]["read_authority"])
            self.assertEqual(1, len(blobs))

    def test_publication_requires_exact_notebook_recovery_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "collector.sqlite3"
            with StateDB(state_path) as state:
                state.create_run(
                    "cohort",
                    mode="reconcile",
                    status="running",
                )
                state.upsert_repository({
                    "node_id": "R_notebook",
                    "full_name": "public/notebook",
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": "a" * 40,
                    "metadata": {},
                })
                task_id = self._failed_attempt(
                    state,
                    task_key="notebook",
                    repository_id="R_notebook",
                    full_name="public/notebook",
                    error_code="invalid_notebook",
                    error_detail="tracked notebook is invalid JSON",
                    retryable=False,
                )
                state.connection.execute(
                    """
                    UPDATE tasks SET status='pending',max_attempts=2,
                        finished_at=NULL WHERE task_id=?
                    """,
                    (task_id,),
                )
                state.lease_task_by_id(
                    task_id, worker="fixture", lease_seconds=300
                )
                result = {
                    "status": "clean_reject",
                    "seconds": 1.0,
                    "current_tree_triage_seconds": 0.5,
                    "history_dating_seconds": 0.0,
                    "analysis_seconds": 0.0,
                    "git_subprocess_count": 1,
                    "network_clone_count": 0,
                    "network_fetch_count": 0,
                    "network_materialized_bytes": 0,
                }
                state.record_scan_attempt_result(
                    task_id,
                    worker="fixture",
                    status="complete",
                    retryable=False,
                    error_code=None,
                    result=result,
                )
                state.complete_task(
                    task_id, worker="fixture", result=result
                )
                with self.assertRaisesRegex(
                    RuntimeError, "recovery certificate"
                ):
                    state.assert_run_publishable("cohort")

                proof = {
                    "version": 1,
                    "kind": (
                        "phase8-exact-malformed-notebook-negative-proof"
                    ),
                    "proofs": [{
                        "task_id": task_id,
                        "retention_token_hits": [],
                    }],
                }
                proof["contract_sha256"] = hashlib.sha256(
                    canonical_json(proof).encode("utf-8")
                ).hexdigest()
                result_json = state.connection.execute(
                    "SELECT result_json FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()[0]
                successes = [{
                    "task_id": task_id,
                    "attempt": 2,
                    "result_sha256": hashlib.sha256(
                        result_json.encode("utf-8")
                    ).hexdigest(),
                }]
                checkpoint = {
                    "version": 1,
                    "proof": proof,
                    "successful_tasks": successes,
                    "successful_tasks_sha256": hashlib.sha256(
                        canonical_json(successes).encode("utf-8")
                    ).hexdigest(),
                    "completed_checkpoint_replayed": 0,
                    "other_budget_changes": 0,
                }
                state.update_stage(
                    "cohort",
                    "phase8_notebook_issue_lane",
                    status="complete",
                    checkpoint=checkpoint,
                )
                state.assert_run_publishable("cohort")

    def test_publication_requires_exact_blocked_lfs_recovery_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "collector.sqlite3"
            with StateDB(state_path) as state:
                state.create_run(
                    "cohort", mode="reconcile", status="running"
                )
                state.upsert_repository({
                    "node_id": "R_lfs",
                    "full_name": "public/lfs",
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": "a" * 40,
                    "metadata": {},
                })
                task_id = self._failed_attempt(
                    state,
                    task_key="lfs",
                    repository_id="R_lfs",
                    full_name="public/lfs",
                    error_code="detector_error",
                    error_detail=(
                        "could not inspect detector-relevant LFS path: "
                        "src/use.py (errno=1)"
                    ),
                    retryable=False,
                )
                state.connection.execute(
                    """
                    UPDATE tasks SET status='pending',max_attempts=2,
                        finished_at=NULL WHERE task_id=?
                    """,
                    (task_id,),
                )
                state.lease_task_by_id(
                    task_id, worker="fixture", lease_seconds=300
                )
                result = {
                    "status": "clean_reject",
                    "seconds": 1.0,
                    "current_tree_triage_seconds": 0.5,
                    "history_dating_seconds": 0.0,
                    "analysis_seconds": 0.0,
                    "git_subprocess_count": 1,
                    "network_clone_count": 0,
                    "network_fetch_count": 0,
                    "network_materialized_bytes": 0,
                }
                state.record_scan_attempt_result(
                    task_id,
                    worker="fixture",
                    status="complete",
                    retryable=False,
                    error_code=None,
                    result=result,
                )
                state.complete_task(
                    task_id, worker="fixture", result=result
                )
                with self.assertRaisesRegex(
                    RuntimeError, "LFS-inspection recovery certificate"
                ):
                    state.assert_run_publishable("cohort")

                proof = {
                    "version": 1,
                    "kind": "phase8-exact-blocked-lfs-inspection-proof",
                    "proofs": [{
                        "task_id": task_id,
                        "lfs_pointer": False,
                        "read_authority": "exact-local-git-blob",
                    }],
                }
                proof["contract_sha256"] = hashlib.sha256(
                    canonical_json(proof).encode("utf-8")
                ).hexdigest()
                result_json = state.connection.execute(
                    "SELECT result_json FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()[0]
                successes = [{
                    "task_id": task_id,
                    "attempt": 2,
                    "result_sha256": hashlib.sha256(
                        result_json.encode("utf-8")
                    ).hexdigest(),
                }]
                checkpoint = {
                    "version": 1,
                    "proof": proof,
                    "successful_tasks": successes,
                    "successful_tasks_sha256": hashlib.sha256(
                        canonical_json(successes).encode("utf-8")
                    ).hexdigest(),
                    "completed_checkpoint_replayed": 0,
                    "other_budget_changes": 0,
                }
                state.update_stage(
                    "cohort",
                    "phase8_lfs_inspection_issue_lane",
                    status="complete",
                    checkpoint=checkpoint,
                )
                state.assert_run_publishable("cohort")


class PublicationGateTests(unittest.TestCase):
    def test_advisory_gaps_are_diagnostic_but_required_gaps_block(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog={},
                    fingerprints={
                        key: "a" * 64
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
                    "gate",
                    mode="reconcile",
                    plan={
                        "execution_contract": {
                            "selected_library_ids": ["cublas"]
                        }
                    },
                    status="running",
                )
                specs = [
                    {
                        "source": source,
                        "library_id": "cublas",
                        "signal_id": "header-00",
                        "query": '"cublas.h"',
                        "query_fingerprint": source + "-fp",
                        "extensions": [],
                        "pack_kind": "header",
                        "member_signal_ids": ["header-00"],
                    }
                    for source in (
                        "github-code-search",
                        "sourcegraph",
                    )
                ]
                for spec in specs:
                    task_id = state.enqueue_task(
                        "gate",
                        "discovery-query",
                        _task_key(spec),
                        library_id="cublas",
                        payload=spec,
                    )
                    if spec["source"] == "github-code-search":
                        document = _document(spec)
                        complete = True
                    else:
                        document = _document(
                            spec,
                            complete=False,
                            gaps=(
                                CoverageGap(
                                    "server_timeout",
                                    "advisory",
                                    retryable=True,
                                ),
                            ),
                        )
                        complete = False
                    _complete_task(state, task_id, document)
                    state.record_discovery_coverage(
                        run_id="gate",
                        library_id="cublas",
                        source=spec["source"],
                        query_fp=spec["query_fingerprint"],
                        partition_key="summary",
                        complete=complete,
                        result_count=1,
                        certificate=document["certificate"],
                    )
                state.record_discovery_coverage(
                    run_id="gate",
                    library_id="cublas",
                    source="github-code-search",
                    query_fp="obsolete",
                    partition_key="summary",
                    complete=False,
                    result_count=0,
                    capped=True,
                    certificate={"terminal": False},
                )
                state.assert_run_publishable("gate")
                state.record_discovery_coverage(
                    run_id="gate",
                    library_id="cublas",
                    source="github-code-search",
                    query_fp="github-code-search-fp",
                    partition_key="summary",
                    complete=False,
                    result_count=0,
                    capped=True,
                    certificate={"terminal": False},
                )
                with self.assertRaisesRegex(
                    RuntimeError, "required discovery coverage"
                ):
                    state.assert_run_publishable("gate")

    def test_retry_replaces_partial_coverage_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cutensor",
                    catalog={},
                    fingerprints={
                        key: "a" * 64
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
                    "retry", mode="reconcile", status="running"
                )
                failed = {
                    "source": "github-code-search",
                    "library_id": "cutensor",
                    "query_fingerprint": "query",
                    "epoch_started_at": "2026-07-29T00:00:00Z",
                    "epoch_completed_at": "2026-07-29T00:01:00Z",
                    "complete": False,
                    "terminal": True,
                    "gaps": [{"code": "search_http_error"}],
                }
                for partition_key in ("failed-a", "failed-b"):
                    state.record_discovery_coverage(
                        run_id="retry",
                        library_id="cutensor",
                        source="github-code-search",
                        query_fp="query",
                        partition_key=partition_key,
                        complete=False,
                        result_count=0,
                        certificate=failed,
                    )
                succeeded = {
                    **failed,
                    "epoch_started_at": "2026-07-29T00:02:00Z",
                    "epoch_completed_at": "2026-07-29T00:03:00Z",
                    "complete": True,
                    "gaps": [],
                }
                state.record_discovery_coverage(
                    run_id="retry",
                    library_id="cutensor",
                    source="github-code-search",
                    query_fp="query",
                    partition_key="success",
                    complete=True,
                    result_count=200,
                    certificate=succeeded,
                )
                rows = list(state.connection.execute(
                    """
                    SELECT partition_key, complete, certificate_json
                    FROM discovery_coverage
                    WHERE run_id='retry' AND library_id='cutensor'
                      AND source='github-code-search' AND query_fp='query'
                    """
                ))
                self.assertEqual(1, len(rows))
                self.assertEqual("success", rows[0]["partition_key"])
                self.assertEqual(1, rows[0]["complete"])
                self.assertEqual(
                    succeeded,
                    json.loads(rows[0]["certificate_json"]),
                )


class StateInheritanceContractTests(unittest.TestCase):
    def test_network_attempt_usage_is_idempotent_and_retry_errors_clear(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog={},
                    fingerprints={
                        key: "a" * 64
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
                    "usage", mode="reconcile", status="running"
                )
                task_id = state.enqueue_task(
                    "usage",
                    "discovery-query",
                    "github:cublas:query",
                    library_id="cublas",
                    payload={
                        "source": "github-code-search",
                        "library_id": "cublas",
                        "query_fingerprint": "query",
                    },
                )
                first = state.lease_task_by_id(
                    task_id, worker="first", lease_seconds=300
                )
                self.assertEqual(1, first["attempts"])
                usage = {
                    "run_id": "usage",
                    "task_id": task_id,
                    "attempt": 1,
                    "source": "github-code-search",
                    "result_status": "failed",
                    "operation_count": 4,
                    "request_attempt_count": 7,
                    "retry_count": 3,
                    "rate_limited_attempts": 3,
                    "server_error_attempts": 0,
                    "network_error_attempts": 0,
                    "budget_rejections": 0,
                }
                self.assertTrue(
                    state.record_network_task_usage(**usage)
                )
                self.assertFalse(
                    state.record_network_task_usage(**usage)
                )
                with self.assertRaisesRegex(
                    RuntimeError, "differs"
                ):
                    state.record_network_task_usage(
                        **{**usage, "request_attempt_count": 8}
                    )
                state.fail_task(
                    task_id,
                    worker="first",
                    error_code="fixture_retry",
                    retry=True,
                )
                second = state.lease_task_by_id(
                    task_id, worker="second", lease_seconds=300
                )
                self.assertEqual(2, second["attempts"])
                state.record_network_task_usage(
                    **{
                        **usage,
                        "attempt": 2,
                        "result_status": "complete",
                        "operation_count": 1,
                        "request_attempt_count": 1,
                        "retry_count": 0,
                        "rate_limited_attempts": 0,
                    }
                )
                state.complete_task(
                    task_id,
                    worker="second",
                    result={
                        "certificate": {
                            "metrics": {"request_count": 1}
                        }
                    },
                )
                row = state.connection.execute(
                    """
                    SELECT status, attempts, error_code FROM tasks
                    WHERE task_id=?
                    """,
                    (task_id,),
                ).fetchone()
                self.assertEqual(
                    ("complete", 2, None),
                    (row["status"], row["attempts"], row["error_code"]),
                )
                totals = state.connection.execute(
                    """
                    SELECT SUM(operation_count), SUM(request_attempt_count),
                           SUM(retry_count)
                    FROM network_task_usage
                    WHERE run_id='usage'
                    """
                ).fetchone()
                self.assertEqual((5, 8, 3), tuple(totals))
                checkpoint = state.checkpoint_document()
                self.assertEqual(
                    2,
                    len(
                        checkpoint["tables"]["network_task_usage"][
                            "rows"
                        ]
                    ),
                )

    def test_discovery_usage_ignores_inherited_metadata_tasks(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.sqlite3"
            executable = "d" * 64
            discovery_payload = {
                "source": "github-code-search",
                "library_id": "cublas",
                "query_fingerprint": "query",
            }
            metadata_payload = {
                "version": 1,
                "lookups": [{
                    "node_id": None,
                    "full_name": "public/example",
                }],
            }
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog={},
                    fingerprints={
                        key: "a" * 64
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
                    "predecessor", mode="reconcile", status="running"
                )
                predecessor_tasks = []
                for stage, key, payload, result in (
                    (
                        "discovery-query",
                        "github:cublas:query",
                        discovery_payload,
                        {
                            "certificate": {
                                "metrics": {"request_count": 7}
                            }
                        },
                    ),
                    (
                        "github-metadata-batch",
                        "batch:fixture",
                        metadata_payload,
                        {"kind": "metadata"},
                    ),
                ):
                    task_id = state.enqueue_task(
                        "predecessor",
                        stage,
                        key,
                        library_id=(
                            "cublas"
                            if stage == "discovery-query"
                            else None
                        ),
                        payload=payload,
                    )
                    _complete_task(state, task_id, result)
                    predecessor_tasks.append(
                        (stage, key, payload, result, task_id)
                    )
                state.abandon_run(
                    "predecessor", reason="fixture_recovery"
                )
                successor, _ = state.create_successor_run(
                    "successor",
                    predecessor_run_id="predecessor",
                    reason="fixture_recovery",
                    compatibility={
                        "network_task_source_sha256": executable
                    },
                    mode="reconcile",
                    plan={},
                    budgets={},
                    fingerprints={},
                    base_release_id="release",
                )
                for stage, key, payload, result, predecessor_id in (
                    predecessor_tasks
                ):
                    task_id = state.enqueue_task(
                        successor,
                        stage,
                        key,
                        library_id=(
                            "cublas"
                            if stage == "discovery-query"
                            else None
                        ),
                        payload=payload,
                    )
                    state.inherit_completed_task(
                        successor_task_id=task_id,
                        predecessor_task_id=predecessor_id,
                        predecessor_run_id="predecessor",
                        payload=payload,
                        result=result,
                        network_task_source_sha256=executable,
                        source_policy="required",
                        inherited_request_count=(
                            7 if stage == "discovery-query" else 99
                        ),
                    )
                usage = _durable_discovery_request_usage(
                    state, successor
                )
                self.assertEqual(
                    7,
                    usage["sources"]["github-code-search"]["charged"],
                )


class CohortRecoveryContractTests(unittest.TestCase):
    def metadata_row(self):
        payload = {
            "version": 1,
            "lookups": [{
                "node_id": None,
                "full_name": "public/example",
            }],
        }
        repository = RepositoryMetadata(
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
        )
        document = _metadata_result_to_task_result(
            GraphQLResolution(
                repositories=(repository,),
                errors=(),
                request_count=1,
                points_used=1,
                remaining=5000,
                reset_at="2026-07-30T00:00:00Z",
            )
        )
        return {
            "task_key": "batch:%06d:%s" % (
                0,
                fingerprint("github-metadata-task", payload)[:32],
            ),
            "payload_json": json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ),
            "result_json": json.dumps(
                document, sort_keys=True, separators=(",", ":")
            ),
            "status": "complete",
        }

    def test_metadata_reuse_requires_exact_payload_result_and_public_shape(self):
        row = self.metadata_row()
        payload, document, resolution = _validated_metadata_task(
            row, ordinal=0
        )
        self.assertEqual(1, len(payload["lookups"]))
        self.assertEqual(1, resolution.request_count)
        self.assertTrue(document["repositories"][0]["admitted_public"])

        changed = dict(row)
        changed["task_key"] = "batch:000000:changed"
        with self.assertRaisesRegex(PipelineError, "task key"):
            _validated_metadata_task(changed, ordinal=0)

        leaked = dict(row)
        value = json.loads(leaked["result_json"])
        value["repositories"][0]["private_field"] = "must-not-survive"
        leaked["result_json"] = json.dumps(
            value, sort_keys=True, separators=(",", ":")
        )
        with self.assertRaisesRegex(PipelineError, "public-safe"):
            _validated_metadata_task(leaked, ordinal=0)

    def test_preflights_reuse_effective_detector_fingerprint(self):
        library = next(
            item for item in config.LIBRARIES
            if item["id"] == "cublas"
        )
        observation = DiscoveryObservation(
            repo_full_name="public/example",
            repo_node_id="R_current",
            library_id="cublas",
            signal_id="header-00",
            source="github-code-search",
            query_fingerprint="a" * 64,
            observed_at=NOW,
            visibility="PUBLIC",
            matched_path="src/example.cu",
        )
        result = DiscoveryResult(
            observations=(observation,),
            quarantined_observations=(),
            certificate=CoverageCertificate(
                source="github-code-search",
                library_id="cublas",
                query_fingerprint="a" * 64,
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
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "data"
            data_dir.mkdir()
            state_path = root / "state.sqlite3"
            budgets = RunBudgets.reconcile()
            plan = build_plan(
                mode="reconcile",
                state_path=state_path,
                data_dir=data_dir,
                libraries=[library],
                weekly_scan_budget=budgets.max_scan_repositories,
                max_graphql_points=budgets.max_graphql_points,
                min_graphql_remaining=budgets.min_graphql_remaining,
            )
            effective_fp = _library_fp_values(
                plan, "cublas"
            )["detector"]
            self.assertNotEqual(
                plan.fingerprints.libraries["cublas"].detector,
                effective_fp,
            )
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog=library,
                    fingerprints=_library_fp_values(plan, "cublas"),
                )
                state.upsert_repository({
                    "node_id": "R_current",
                    "full_name": "public/example",
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                    "default_branch": "main",
                    "head_sha": "a" * 40,
                    "metadata": {
                        "requested_full_name": "public/example",
                    },
                })
                state.record_scan_result(
                    repository_id="R_current",
                    library_id="cublas",
                    head_sha="a" * 40,
                    detector_fp=effective_fp,
                    classification="confirmed",
                    status="clean",
                )
                candidate = _cohort_candidate_preflight(
                    state=state,
                    data_dir=data_dir,
                    libraries=[library],
                    validated_tasks={
                        "fixture": ({}, result, 1),
                    },
                    plan=plan,
                    budgets=budgets,
                    repo_root=root,
                )
                recovery, _metadata = _cohort_recovery_preflight(
                    state=state,
                    data_dir=data_dir,
                    libraries=[library],
                    validated_tasks={
                        "fixture": ({}, result, 1),
                    },
                    metadata_rows=[self.metadata_row()],
                    plan=plan,
                    budgets=budgets,
                    repo_root=root,
                )
        for report in (candidate, recovery):
            self.assertEqual(
                1, report["reusable_repository_library_pairs"]
            )
            self.assertEqual(0, report["predicted_scan_repositories"])

    def test_recovery_fingerprint_contract_allows_detector_only(self):
        old = {
            "dating": "d",
            "ai": "a",
            "filters": "f",
            "aggregation": "g",
            "publication": "p",
            "libraries": {
                "cublas": {
                    "discovery": "one",
                    "detector": "old",
                    "presentation": "same",
                }
            },
        }
        new = copy.deepcopy(old)
        new["libraries"]["cublas"]["detector"] = "new"
        audit = _assert_cohort_fingerprint_compatibility(
            old, new, identity_scan_remediation=True
        )
        self.assertFalse(audit["scan_reuse_compatible"])
        self.assertEqual(["cublas"], audit["changed_library_ids"])
        changed = copy.deepcopy(new)
        changed["libraries"]["cublas"]["discovery"] = "changed"
        with self.assertRaisesRegex(
            PipelineError, "non-detector"
        ):
            _assert_cohort_fingerprint_compatibility(
                old, changed, identity_scan_remediation=True
            )

    def test_control_plane_fingerprint_contract_requires_explicit_mode(self):
        frozen = {
            "dating": "d",
            "ai": "a",
            "filters": "f",
            "aggregation": "g",
            "publication": "p",
            "libraries": {
                "cublas": {
                    "discovery": "same",
                    "detector": "same",
                    "presentation": "same",
                }
            },
        }
        with self.assertRaisesRegex(
            PipelineError, "did not invalidate remediated scans"
        ):
            _assert_cohort_fingerprint_compatibility(
                frozen,
                copy.deepcopy(frozen),
                identity_scan_remediation=True,
            )
        audit = _assert_cohort_fingerprint_compatibility(
            frozen,
            copy.deepcopy(frozen),
            identity_scan_remediation=True,
            allow_unchanged_detector_fingerprints=True,
        )
        self.assertTrue(audit["scan_reuse_compatible"])
        self.assertEqual([], audit["changed_library_ids"])

    def test_control_plane_import_audit_identifies_only_added_module(self):
        before = b"import os\nimport resource\n"
        after = b"import os\nimport re\nimport resource\n"
        self.assertEqual(
            {"os", "resource"}, _module_import_names(before)
        )
        self.assertEqual(
            {"os", "re", "resource"}, _module_import_names(after)
        )

    def test_discovery_accounting_audit_normalizes_only_stage_filter(self):
        current = (
            ROOT / "collector" / "pipeline.py"
        ).read_bytes()
        predecessor = current.replace(
            b"\\n          AND t.stage='discovery-query'",
            b"",
            1,
        )
        self.assertEqual(
            _normalized_discovery_usage_digest(predecessor),
            _normalized_discovery_usage_digest(current),
        )
        changed = current.replace(
            b"network usage run is unknown",
            b"network usage run differs",
            1,
        )
        self.assertNotEqual(
            _normalized_discovery_usage_digest(current),
            _normalized_discovery_usage_digest(changed),
        )

    def test_recovery_successor_is_exact_and_idempotent(self):
        disk_patch = mock.patch(
            "collector.successor.shutil.disk_usage",
            return_value=shutil._ntuple_diskusage(
                4 * 1024**4,
                1024**3,
                4 * 1024**4 - 1024**3,
            ),
        )
        disk_patch.start()
        self.addCleanup(disk_patch.stop)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            (data / "v2").mkdir(parents=True)
            (data / "v2" / "manifest.json").write_text(
                json.dumps({"release": {"id": "fixture-release"}})
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
            predecessor_fingerprints["libraries"]["cublas"][
                "detector"
            ] = "0" * 64
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
            with StateDB(state_path) as state:
                library = next(
                    item
                    for item in config.LIBRARIES
                    if item["id"] == "cublas"
                )
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
                    PREDECESSOR,
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
                specs = [
                    spec
                    for spec in _discovery_specs([library])
                ]
                for spec in specs:
                    task_id = state.enqueue_task(
                        PREDECESSOR,
                        "discovery-query",
                        _task_key(spec),
                        library_id="cublas",
                        payload=spec,
                    )
                    _complete_task(state, task_id, _document(spec))
                metadata = self.metadata_row()
                task_id = state.enqueue_task(
                    PREDECESSOR,
                    "github-metadata-batch",
                    metadata["task_key"],
                    payload=json.loads(metadata["payload_json"]),
                )
                _complete_task(
                    state,
                    task_id,
                    json.loads(metadata["result_json"]),
                )
                state.abandon_run(
                    PREDECESSOR,
                    reason="candidate_identity_scan_remediation",
                )
            audit = {
                "predecessor_network_task_source_sha256": (
                    old_executable
                ),
                "successor_network_task_source_sha256": (
                    new_executable
                ),
                "per_task_execution_equivalent": True,
                "remediation_kind": (
                    "candidate-identity-and-scan-reliability"
                ),
            }
            with mock.patch(
                "collector.successor._cohort_successor_source_audit",
                return_value=audit,
            ), mock.patch(
                "collector.successor.shutil.disk_usage",
                return_value=shutil._ntuple_diskusage(
                    4 * 1024**4,
                    1024**3,
                    4 * 1024**4 - 1024**3,
                ),
            ):
                first = prepare_phase8_cohort_successor(
                    repo_root=root,
                    state_path=state_path,
                    data_dir=data,
                    predecessor_run_id=PREDECESSOR,
                    predecessor_source_ref="fixture",
                    reason="candidate_identity_scan_remediation",
                    budgets=budgets,
                    recovery_remediation=True,
                )
                second = prepare_phase8_cohort_successor(
                    repo_root=root,
                    state_path=state_path,
                    data_dir=data,
                    predecessor_run_id=PREDECESSOR,
                    predecessor_source_ref="fixture",
                    reason="candidate_identity_scan_remediation",
                    budgets=budgets,
                    recovery_remediation=True,
                )
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertEqual(
                first["successor_run_id"],
                second["successor_run_id"],
            )
            self.assertEqual(len(specs), first["inherited_tasks"])
            self.assertEqual(1, first["inherited_metadata_tasks"])
            self.assertEqual(0, first["pending_tasks"])
            self.assertEqual(
                1, first["preflight"]["predicted_scan_repositories"]
            )
            self.assertEqual(
                "detector_fingerprint_changed",
                first["scan_reuse_refusal_reason"],
            )
            with StateDB(state_path) as state:
                stages = {
                    row["stage"]: row["status"]
                    for row in state.connection.execute(
                        """
                        SELECT stage, status FROM tasks
                        WHERE run_id=?
                        """,
                        (first["successor_run_id"],),
                    )
                }
                self.assertEqual(
                    {
                        "discovery-query": "complete",
                        "github-metadata-batch": "complete",
                    },
                    stages,
                )
                state.abandon_run(
                    first["successor_run_id"],
                    reason="preseed_contract_validator_import",
                )
            control_audit = {
                "predecessor_network_task_source_sha256": (
                    new_executable
                ),
                "successor_network_task_source_sha256": "c" * 64,
                "per_task_execution_equivalent": True,
                "control_plane_import_only": True,
                "remediation_kind": (
                    "preseed-contract-validator-import"
                ),
            }
            with mock.patch(
                "collector.successor._cohort_successor_source_audit",
                return_value=control_audit,
            ), mock.patch(
                "collector.successor.shutil.disk_usage",
                return_value=shutil._ntuple_diskusage(
                    4 * 1024**4,
                    1024**3,
                    4 * 1024**4 - 1024**3,
                ),
            ):
                control = prepare_phase8_cohort_successor(
                    repo_root=root,
                    state_path=state_path,
                    data_dir=data,
                    predecessor_run_id=first["successor_run_id"],
                    predecessor_source_ref="fixture",
                    reason="preseed_contract_validator_import",
                    budgets=budgets,
                    recovery_remediation=True,
                    control_plane_remediation=True,
                )
            self.assertTrue(control["created"])
            self.assertEqual(0, control["pending_tasks"])
            self.assertEqual(0, control["refused_scan_tasks"])
            self.assertIsNone(
                control["scan_reuse_refusal_reason"]
            )
            self.assertEqual(
                len(specs) + 1,
                control["predecessor_inherited_tasks"],
            )
            with StateDB(state_path) as state:
                state.upsert_repository({
                    "node_id": "R_current",
                    "full_name": "public/example",
                    "visibility": "public",
                    "head_sha": "a" * 40,
                })
                scan_task = state.enqueue_task(
                    control["successor_run_id"],
                    "scan",
                    "public/example",
                    repository_id="R_current",
                    payload={
                        "full_name": "public/example",
                        "head_sha": "a" * 40,
                        "libraries": ["cublas"],
                    },
                )
                _complete_task(
                    state,
                    scan_task,
                    {
                        "status": "match",
                        "seconds": 1.0,
                        "current_tree_triage_seconds": 0.25,
                        "history_dating_seconds": 0.5,
                        "analysis_seconds": 0.25,
                        "git_subprocess_count": 1,
                        "network_clone_count": 0,
                        "network_fetch_count": 0,
                        "network_materialized_bytes": 0,
                    },
                )
                state.abandon_run(
                    control["successor_run_id"],
                    reason="fixture_control_recovery",
                )
            with self.assertRaisesRegex(
                PipelineError, "predecessor with completed scans"
            ):
                prepare_phase8_cohort_successor(
                    repo_root=root,
                    state_path=state_path,
                    data_dir=data,
                    predecessor_run_id=control["successor_run_id"],
                    predecessor_source_ref="fixture",
                    reason="fixture_control_recovery",
                    budgets=budgets,
                    recovery_remediation=True,
                    control_plane_remediation=True,
                )
            with StateDB(state_path) as state:
                frozen = json.loads(
                    state.connection.execute(
                        """
                        SELECT fingerprints_json FROM runs
                        WHERE run_id=?
                        """,
                        (control["successor_run_id"],),
                    ).fetchone()[0]
                )
                frozen["libraries"]["cublas"]["detector"] = "0" * 64
                with state.transaction():
                    state.connection.execute(
                        """
                        UPDATE runs SET fingerprints_json=?
                        WHERE run_id=?
                        """,
                        (
                            json.dumps(
                                frozen,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                            control["successor_run_id"],
                        ),
                    )
            scan_runtime_audit = {
                "predecessor_network_task_source_sha256": "c" * 64,
                "successor_network_task_source_sha256": "c" * 64,
                "per_task_execution_equivalent": True,
                "scan_runtime_only": True,
                "remediation_kind": (
                    "git-lfs-checkout-and-content-availability"
                ),
            }
            with mock.patch(
                "collector.successor._cohort_successor_source_audit",
                return_value=scan_runtime_audit,
            ):
                scan_runtime = prepare_phase8_cohort_successor(
                    repo_root=root,
                    state_path=state_path,
                    data_dir=data,
                    predecessor_run_id=control["successor_run_id"],
                    predecessor_source_ref="fixture",
                    reason="git_lfs_checkout_remediation",
                    budgets=budgets,
                    recovery_remediation=True,
                    scan_runtime_remediation=True,
                )
            self.assertTrue(scan_runtime["created"])
            self.assertEqual(0, scan_runtime["pending_tasks"])
            self.assertEqual(1, scan_runtime["refused_scan_tasks"])
            self.assertEqual(
                "detector_fingerprint_changed",
                scan_runtime["scan_reuse_refusal_reason"],
            )
            with StateDB(state_path) as state:
                self.assertEqual(
                    0,
                    state.connection.execute(
                        """
                        SELECT COUNT(*) FROM tasks
                        WHERE run_id=? AND stage='scan'
                        """,
                        (scan_runtime["successor_run_id"],),
                    ).fetchone()[0],
                )
                state.abandon_run(
                    scan_runtime["successor_run_id"],
                    reason="effective_detector_preflight_reuse",
                )
            preflight_audit = {
                "predecessor_network_task_source_sha256": "c" * 64,
                "successor_network_task_source_sha256": "c" * 64,
                "per_task_execution_equivalent": True,
                "preflight_reuse_only": True,
                "remediation_kind": (
                    "effective-detector-preflight-reuse"
                ),
            }
            with mock.patch(
                "collector.successor._cohort_successor_source_audit",
                return_value=preflight_audit,
            ):
                preflight_reuse = prepare_phase8_cohort_successor(
                    repo_root=root,
                    state_path=state_path,
                    data_dir=data,
                    predecessor_run_id=scan_runtime[
                        "successor_run_id"
                    ],
                    predecessor_source_ref="fixture",
                    reason="effective_detector_preflight_reuse",
                    budgets=budgets,
                    recovery_remediation=True,
                    preflight_reuse_remediation=True,
                )
            self.assertTrue(preflight_reuse["created"])
            self.assertEqual(0, preflight_reuse["pending_tasks"])
            self.assertEqual(0, preflight_reuse["refused_scan_tasks"])
            self.assertIsNone(
                preflight_reuse["scan_reuse_refusal_reason"]
            )
            with StateDB(state_path) as state:
                preflight_plan = json.loads(
                    state.connection.execute(
                        "SELECT plan_json FROM runs WHERE run_id=?",
                        (preflight_reuse["successor_run_id"],),
                    ).fetchone()[0]
                )
            self.assertEqual(
                "phase8-partial-cohort-preflight-reuse-recovery",
                preflight_plan["successor_lineage"]["kind"],
            )
            with StateDB(state_path) as state:
                state.abandon_run(
                    preflight_reuse["successor_run_id"],
                    reason="lineage_scan_budget_preflight",
                )
            preflight_budget_audit = {
                "predecessor_network_task_source_sha256": "c" * 64,
                "successor_network_task_source_sha256": "c" * 64,
                "per_task_execution_equivalent": True,
                "preflight_budget_only": True,
                "remediation_kind": "lineage-scan-budget-preflight",
            }
            with mock.patch(
                "collector.successor._cohort_successor_source_audit",
                return_value=preflight_budget_audit,
            ):
                preflight_budget = prepare_phase8_cohort_successor(
                    repo_root=root,
                    state_path=state_path,
                    data_dir=data,
                    predecessor_run_id=preflight_reuse[
                        "successor_run_id"
                    ],
                    predecessor_source_ref="fixture",
                    reason="lineage_scan_budget_preflight",
                    budgets=budgets,
                    recovery_remediation=True,
                    preflight_budget_remediation=True,
                )
            self.assertTrue(preflight_budget["created"])
            self.assertEqual(0, preflight_budget["pending_tasks"])
            self.assertEqual(0, preflight_budget["refused_scan_tasks"])
            self.assertIsNone(
                preflight_budget["scan_reuse_refusal_reason"]
            )
            with StateDB(state_path) as state:
                preflight_budget_plan = json.loads(
                    state.connection.execute(
                        "SELECT plan_json FROM runs WHERE run_id=?",
                        (preflight_budget["successor_run_id"],),
                    ).fetchone()[0]
                )
            self.assertEqual(
                "phase8-partial-cohort-preflight-budget-recovery",
                preflight_budget_plan["successor_lineage"]["kind"],
            )
            dispatches = preflight_budget_plan["cohort_preflight"][
                "scan_dispatch_attempts"
            ]
            self.assertEqual(
                dispatches["historical_charged"]
                + dispatches["planned_new"],
                dispatches["combined_upper"],
            )

    def test_changed_payload_and_executable_hash_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.sqlite3"
            executable = "d" * 64
            payload = {
                "source": "github-code-search",
                "library_id": "cublas",
                "query_fingerprint": "query",
            }
            result = {"kind": "fixture", "visibility": "public"}
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog={},
                    fingerprints={
                        key: "a" * 64
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
                    "predecessor", mode="reconcile", status="running"
                )
                predecessor_task = state.enqueue_task(
                    "predecessor",
                    "discovery-query",
                    "github:cublas:query",
                    library_id="cublas",
                    payload=payload,
                )
                _complete_task(state, predecessor_task, result)
                state.abandon_run(
                    "predecessor", reason="fixture_scope_reduction"
                )
                successor_id, _created = state.create_successor_run(
                    "successor",
                    predecessor_run_id="predecessor",
                    reason="fixture_scope_reduction",
                    compatibility={
                        "network_task_source_sha256": executable
                    },
                    mode="reconcile",
                    plan={},
                    budgets={},
                    fingerprints={},
                    base_release_id="release",
                )
                successor_task = state.enqueue_task(
                    successor_id,
                    "discovery-query",
                    "github:cublas:query",
                    library_id="cublas",
                    payload=payload,
                )
                with self.assertRaisesRegex(
                    RuntimeError, "payload or result changed"
                ):
                    state.inherit_completed_task(
                        successor_task_id=successor_task,
                        predecessor_task_id=predecessor_task,
                        predecessor_run_id="predecessor",
                        payload={**payload, "query_fingerprint": "changed"},
                        result=result,
                        network_task_source_sha256=executable,
                        source_policy="required",
                        inherited_request_count=1,
                    )
                with self.assertRaisesRegex(
                    RuntimeError, "executable fingerprint changed"
                ):
                    state.inherit_completed_task(
                        successor_task_id=successor_task,
                        predecessor_task_id=predecessor_task,
                        predecessor_run_id="predecessor",
                        payload=payload,
                        result=result,
                        network_task_source_sha256="e" * 64,
                        source_policy="required",
                        inherited_request_count=1,
                    )
                self.assertTrue(state.inherit_completed_task(
                    successor_task_id=successor_task,
                    predecessor_task_id=predecessor_task,
                    predecessor_run_id="predecessor",
                    payload=payload,
                    result=result,
                    network_task_source_sha256=executable,
                    source_policy="required",
                    inherited_request_count=1,
                ))
                provenance = state.connection.execute(
                    """
                    SELECT result_sha256, inherited_request_count
                    FROM task_inheritance
                    WHERE successor_task_id=?
                    """,
                    (successor_task,),
                ).fetchone()
                self.assertRegex(provenance["result_sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(
                    1, provenance["inherited_request_count"]
                )


class CohortDerivationTests(unittest.TestCase):
    @staticmethod
    def _spec(library_id, source):
        return {
            "source": source,
            "library_id": library_id,
            "signal_id": "header-00",
            "query": '"header.h"',
            "query_fingerprint": (
                ("a" if source == "sourcegraph" else "b") * 64
            ),
            "extensions": [] if source == "sourcegraph" else ["h"],
            "pack_kind": "header",
            "member_signal_ids": ["header-00"],
        }

    def _fixture(self):
        libraries = [{"id": "selected"}, {"id": "partial"}]
        specs = {}
        rows = {}
        for library in libraries:
            for source in ("sourcegraph", "github-code-search"):
                spec = self._spec(library["id"], source)
                key = _task_key(spec)
                specs[key] = spec
                rows[key] = {
                    "status": (
                        "pending"
                        if library["id"] == "partial"
                        and source == "github-code-search"
                        else "complete"
                    ),
                    "payload_json": json.dumps(
                        spec, sort_keys=True, separators=(",", ":")
                    ),
                    "result_json": json.dumps(
                        _document(spec),
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                }
        return libraries, specs, rows

    def test_exact_complete_library_selected_without_partial_expansion(self):
        libraries, specs, rows = self._fixture()
        selected, validated, report = _derive_certified_cohort(
            rows, libraries, specs
        )
        self.assertEqual(["selected"], [item["id"] for item in selected])
        self.assertEqual(2, len(validated))
        self.assertEqual(
            {"pending": 1, "complete": 1},
            report["excluded_libraries"]["partial"]["statuses"],
        )

    def test_changed_payload_and_nonpublic_result_are_refused(self):
        libraries, specs, rows = self._fixture()
        selected_key = next(
            key
            for key, spec in specs.items()
            if spec["library_id"] == "selected"
        )
        rows[selected_key]["payload_json"] = "{}"
        with self.assertRaisesRegex(PipelineError, "payload changed"):
            _derive_certified_cohort(rows, libraries, specs)

        libraries, specs, rows = self._fixture()
        selected_key = next(
            key
            for key, spec in specs.items()
            if spec["library_id"] == "selected"
        )
        document = json.loads(rows[selected_key]["result_json"])
        document["observations"][0]["visibility"] = "PRIVATE"
        rows[selected_key]["result_json"] = json.dumps(
            document, sort_keys=True, separators=(",", ":")
        )
        with self.assertRaisesRegex(PipelineError, "not certifiable"):
            _derive_certified_cohort(rows, libraries, specs)

    def test_already_reduced_cohort_can_be_recertified_without_expansion(self):
        libraries, specs, rows = self._fixture()
        selected_library = [libraries[0]]
        selected_specs = {
            key: spec
            for key, spec in specs.items()
            if spec["library_id"] == "selected"
        }
        selected_rows = {
            key: rows[key] for key in selected_specs
        }
        selected, validated, report = _derive_certified_cohort(
            selected_rows,
            selected_library,
            selected_specs,
            require_strict_reduction=False,
        )
        self.assertEqual(["selected"], [item["id"] for item in selected])
        self.assertEqual(set(selected_specs), set(validated))
        self.assertEqual(0, report["excluded_library_count"])

    def test_preflight_graphql_budget_uses_raw_metadata_universe(self):
        library = next(
            item for item in config.LIBRARIES
            if item["id"] == "cublas"
        )
        observations = tuple(
            DiscoveryObservation(
                repo_full_name=(
                    "public/example"
                    if ordinal == 0
                    else "NVIDIA/excluded-%02d" % ordinal
                ),
                library_id="cublas",
                signal_id="header-00",
                source="github-code-search",
                query_fingerprint="a" * 64,
                observed_at=NOW,
                visibility="PUBLIC",
                matched_path="src/example.cu",
            )
            for ordinal in range(52)
        )
        result = DiscoveryResult(
            observations=observations,
            quarantined_observations=(),
            certificate=CoverageCertificate(
                source="github-code-search",
                library_id="cublas",
                query_fingerprint="a" * 64,
                epoch_started_at=NOW,
                epoch_completed_at=NOW,
                complete=True,
                terminal=True,
                observations_count=len(observations),
                quarantined_count=0,
                gaps=(),
                metrics={"request_count": 1},
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "data"
            data_dir.mkdir()
            state_path = root / "state.sqlite3"
            plan = build_plan(
                mode="reconcile",
                state_path=state_path,
                data_dir=data_dir,
                libraries=[library],
                weekly_scan_budget=60_000,
                max_graphql_points=2_500,
                min_graphql_remaining=2_500,
            )
            with StateDB(state_path) as state:
                report = _cohort_candidate_preflight(
                    state=state,
                    data_dir=data_dir,
                    libraries=[library],
                    validated_tasks={
                        "fixture": ({}, result, 1),
                    },
                    plan=plan,
                    budgets=RunBudgets.reconcile(),
                    repo_root=root,
                )
        self.assertEqual(52, report["raw_unique_candidate_repositories"])
        self.assertEqual(1, report["unique_candidate_repositories"])
        self.assertEqual(52, report["metadata_repository_universe"])
        self.assertEqual(2, report["estimated_graphql_requests"])
        self.assertEqual(4, report["planned_graphql_requests"])

    def test_preflight_excludes_only_the_exact_reviewed_collision(self):
        library = next(
            item for item in config.LIBRARIES
            if item["id"] == "cutensor"
        )

        def result(blob):
            observation = DiscoveryObservation(
                repo_full_name="aarnphm/aarnphm.github.io",
                repo_node_id="R_public_example",
                library_id="cutensor",
                signal_id="broad-00",
                source="github-code-search",
                query_fingerprint="a" * 64,
                observed_at=NOW,
                visibility="PUBLIC",
                matched_path="content/lectures/420/index.md",
                matched_blob=blob,
                partition="fixture",
            )
            return DiscoveryResult(
                observations=(observation,),
                quarantined_observations=(),
                certificate=CoverageCertificate(
                    source="github-code-search",
                    library_id="cutensor",
                    query_fingerprint="a" * 64,
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

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "data"
            data_dir.mkdir()
            state_path = root / "state.sqlite3"
            plan = build_plan(
                mode="reconcile",
                state_path=state_path,
                data_dir=data_dir,
                libraries=[library],
                weekly_scan_budget=60_000,
                max_graphql_points=2_500,
                min_graphql_remaining=2_500,
            )
            with StateDB(state_path) as state:
                excluded = _cohort_candidate_preflight(
                    state=state,
                    data_dir=data_dir,
                    libraries=[library],
                    validated_tasks={
                        "fixture": ({}, result(
                            "d9e1feb37ad1930e04e092c3dff19949c8cd684c"
                        ), 1),
                    },
                    plan=plan,
                    budgets=RunBudgets.reconcile(),
                    repo_root=root,
                )
                changed = _cohort_candidate_preflight(
                    state=state,
                    data_dir=data_dir,
                    libraries=[library],
                    validated_tasks={
                        "fixture": ({}, result("b" * 40), 1),
                    },
                    plan=plan,
                    budgets=RunBudgets.reconcile(),
                    repo_root=root,
                )
        self.assertEqual(0, excluded["unique_candidate_repositories"])
        self.assertEqual(0, excluded["predicted_scan_repositories"])
        self.assertEqual(1, changed["unique_candidate_repositories"])
        self.assertEqual(1, changed["predicted_scan_repositories"])


if __name__ == "__main__":
    unittest.main()
