import copy
import dataclasses
import datetime
import hashlib
import io
import json
import os
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from collector import cli, triage as triage_module
from collector.catalog import CATALOG, CATALOG_EVENTS
from collector.cli import _budget, _validate, build_parser
from collector.discovery import (
    CoverageCertificate,
    CoverageGap,
    CoveragePartition,
    DiscoveryObservation,
    DiscoveryResult,
    github_query_fingerprint,
    query_packs,
    sourcegraph_query_fingerprint,
)
from collector.github_client import (
    GraphQLError,
    GraphQLResolution,
    RepositoryMetadata,
)
from collector.phase8_issue_lane import (
    _encoded_token_pattern,
    _exact_blocked_worktree_reads,
    _exact_notebook_negatives,
    _tolerant_notebook_source_text,
    _verify_negative_blob,
)
from collector.pipeline import (
    BudgetExceeded,
    CollectorPipeline,
    NETWORK_TASK_LEASE_SECONDS,
    NO_LIVE_V2_RELEASE,
    PHASE8_MAX_OWNER_WALL_SECONDS,
    PHASE8_ISSUE_RETRY_WORKERS,
    PipelineError,
    RunBudgets,
    WARM_NO_CHANGE_CEILING_SECONDS,
    WARM_NO_CHANGE_TARGET_SECONDS,
    WORK_TASK_LEASE_SECONDS,
    _carry_forward_unselected_v1,
    _carry_forward_coverage_certificates,
    _assert_final_visibility_part,
    _assert_final_visibility_fresh,
    _discovery_observation_excluded,
    _graphql_journal_budget,
    _discovery_stats,
    _github_query_fp,
    _library_repository_excluded,
    _library_fp_values,
    _materialize_family_rollup_entries,
    _restore_direct_parent_entries,
    _preserve_nvpl_component_memberships,
    _metadata_input_context_sha256,
    _metadata_result_to_task_result,
    _network_task_source_sha256,
    _issue_retry_workers,
    _phase8_runtime_issue_contract,
    _phase8_effective_privacy_control,
    _pin_phase8_scan_bound_metadata,
    _retirement_eligible_library_ids,
    _rss_usage_bytes,
    _scan_classification_inventory,
    _should_force_metadata_refresh_after_final_visibility,
    _should_resume_incomplete_fresh_metadata_epoch,
    _should_resume_final_visibility_epoch,
    _slo_profile,
    _TaskLeaseHeartbeat,
    _validate_reviewed_execution_contract,
    signal_specs,
)
from collector.config import LIBRARIES
from collector.fingerprints import canonical_json, fingerprint
from collector.planner import build_plan, current_fingerprints
from collector.nvpl_components import reviewed_components
from collector.scanner_v2 import (
    SCAN_FRESHNESS,
    SCAN_POLICY,
    ScanOutcome,
    _scan_error_contract,
)
from collector.state import StateDB
from collector.validate_v2 import validate_v2


NOW = datetime.datetime(2026, 7, 27, tzinfo=datetime.timezone.utc)


class FakeDiscovery:
    def __init__(self, source, full_name="public/example"):
        self.source = source
        self.full_name = full_name
        self.calls = 0

    def search(
        self,
        *,
        library_id,
        signal_id,
        query,
        query_fingerprint=None,
        **_kwargs,
    ):
        self.calls += 1
        query_fingerprint = query_fingerprint or "%s-%s-%d" % (
            self.source,
            signal_id,
            self.calls,
        )
        observation = DiscoveryObservation(
            repo_full_name=self.full_name,
            repo_node_id="R_public_example" if self.source == "github-code-search" else None,
            library_id=library_id,
            signal_id=signal_id,
            source=self.source,
            query_fingerprint=query_fingerprint,
            observed_at=NOW,
            visibility="PUBLIC",
            matched_path="src/example.cu",
            matched_blob="a" * 40 if self.source == "github-code-search" else None,
            matched_commit="a" * 40 if self.source == "sourcegraph" else None,
            partition="fixture",
        )
        partition = CoveragePartition(
            key="fixture",
            query=query,
            total_count=1,
            fetched_count=1,
            page_count=1,
            complete=True,
        )
        certificate = CoverageCertificate(
            source=self.source,
            library_id=library_id,
            query_fingerprint=observation.query_fingerprint,
            epoch_started_at=NOW,
            epoch_completed_at=NOW,
            complete=True,
            terminal=True,
            observations_count=1,
            partitions=(partition,),
        )
        return DiscoveryResult((observation,), (), certificate)


class FakeMetadata:
    def __init__(self, full_name="public/example"):
        self.full_name = full_name

    def resolve(self, lookups, **_kwargs):
        lookups = list(lookups)
        repositories = []
        for lookup in lookups:
            repositories.append(RepositoryMetadata(
                request_key=lookup.key,
                requested_node_id=lookup.node_id,
                requested_full_name=lookup.full_name,
                node_id="R_public_example",
                full_name=self.full_name,
                visibility="PUBLIC",
                is_private=False,
                is_fork=False,
                is_archived=False,
                default_branch="main",
                head_oid="a" * 40,
                renamed=False,
                status="ok",
            ))
        return GraphQLResolution(
            tuple(repositories), (), 1, 1, 4_999, "2026-07-27T17:00:00Z"
        )


class MutableVisibilityMetadata(FakeMetadata):
    """Fixture that can change visibility between scan and final authority."""

    def __init__(self):
        super().__init__()
        self.private = False
        self.partial = False
        self.initial_calls = 0
        self.final_calls = 0

    def resolve(self, lookups, **_kwargs):
        lookups = list(lookups)
        final = bool(lookups) and all(
            lookup.node_id and lookup.full_name is None
            for lookup in lookups
        )
        if final:
            self.final_calls += 1
        else:
            self.initial_calls += 1
        repositories = []
        errors = ()
        for lookup in lookups:
            partial = final and self.partial
            private = self.private
            repositories.append(RepositoryMetadata(
                request_key=lookup.key,
                requested_node_id=lookup.node_id,
                requested_full_name=lookup.full_name,
                node_id=lookup.node_id or "R_public_example",
                full_name=(
                    None
                    if private or partial
                    else self.full_name
                ),
                visibility="PRIVATE" if private else (
                    None if partial else "PUBLIC"
                ),
                is_private=True if private else (
                    None if partial else False
                ),
                is_fork=None if private or partial else False,
                is_archived=None if private or partial else False,
                default_branch=None if private or partial else "main",
                head_oid=None if private or partial else "a" * 40,
                renamed=False,
                status=(
                    "partial_error"
                    if partial
                    else "private" if private else "ok"
                ),
                errors=("fixture partial",) if partial else (),
            ))
        if final and self.partial:
            errors = (
                GraphQLError(
                    message="fixture partial",
                    request_key=lookups[0].key,
                    error_type="fixture",
                ),
            )
        return GraphQLResolution(
            tuple(repositories),
            errors,
            1,
            1,
            4_999 - self.initial_calls - self.final_calls,
            "2026-07-27T17:00:00Z",
        )


class CrashOnceDiscovery(FakeDiscovery):
    def __init__(self, source, full_name="public/example"):
        super().__init__(source, full_name)
        self.crashed = False

    def search(self, **kwargs):
        if not self.crashed:
            self.calls += 1
            self.crashed = True
            raise OSError("synthetic discovery crash")
        return super().search(**kwargs)


class IncompleteDiscovery(FakeDiscovery):
    def search(
        self,
        *,
        library_id,
        signal_id,
        query,
        query_fingerprint=None,
        **_kwargs,
    ):
        self.calls += 1
        query_fingerprint = query_fingerprint or "incomplete"
        gap = CoverageGap(
            "unexpected_skip",
            "fixture shard limit",
            retryable=True,
        )
        partition = CoveragePartition(
            key="fixture",
            query=query,
            total_count=0,
            fetched_count=0,
            page_count=1,
            complete=False,
            incomplete_results=True,
            gaps=(gap,),
        )
        certificate = CoverageCertificate(
            source=self.source,
            library_id=library_id,
            query_fingerprint=query_fingerprint,
            epoch_started_at=NOW,
            epoch_completed_at=NOW,
            complete=False,
            terminal=True,
            observations_count=0,
            partitions=(partition,),
            gaps=(gap,),
        )
        return DiscoveryResult((), (), certificate)


class CrashNearEndMetadata:
    batch_size = 1

    def __init__(self, crash_key="name:public/legacy-b"):
        self.crash_key = crash_key
        self.crashed = False
        self.calls = []

    def resolve(self, lookups, **_kwargs):
        lookups = list(lookups)
        if len(lookups) != 1:
            raise AssertionError("fixture requires one immutable batch")
        lookup = lookups[0]
        self.calls.append(lookup.key)
        if lookup.key == self.crash_key and not self.crashed:
            self.crashed = True
            raise OSError("synthetic metadata crash")
        full_name = lookup.full_name or {
            "R_public_example": "public/example",
            "R_legacy_a": "public/legacy-a",
            "R_legacy_b": "public/legacy-b",
        }.get(lookup.node_id, "public/example")
        node_id = lookup.node_id or (
            "R_public_example"
            if full_name == "public/example"
            else "R_" + full_name.rsplit("/", 1)[-1].replace("-", "_")
        )
        metadata = RepositoryMetadata(
            request_key=lookup.key,
            requested_node_id=lookup.node_id,
            requested_full_name=lookup.full_name,
            node_id=node_id,
            full_name=full_name,
            visibility="PUBLIC",
            is_private=False,
            is_fork=False,
            is_archived=False,
            default_branch="main",
            head_oid=(node_id[-1].lower() or "a") * 40,
            renamed=False,
            status="ok",
        )
        return GraphQLResolution(
            (metadata,), (), 1, 1, 4_999, "2026-07-27T17:00:00Z"
        )


def fake_scan_runner(tasks, libraries, cache_root, on_result, **_kwargs):
    outcomes = []
    for task in tasks:
        if _kwargs.get("before_task"):
            _kwargs["before_task"](task)
        row = {
            "classification": "confirmed",
            "language": "CUDA",
            "first_integration": "2026-07-01",
            "first_integration_commit": "b" * 12,
            "own_source_files": ["src/example.cu"],
            "own_source_file_count": 1,
            "vendored_present": False,
            "ai_on_integration_commit": False,
            "ai_on_integration_agents": [],
            "operators": [],
        }
        outcome = ScanOutcome(
            full_name=task.full_name,
            head_sha=task.head_sha,
            status="match",
            result={
                "total_commits": 1,
                "ai_agents": {},
                "ai_config_files": [],
                "citation_cff_files": [],
                "citation_cff": {},
                "triage": {
                    "files_examined": 1,
                    "bytes_examined": 20,
                    "skipped_large_files": 0,
                    "pruned_large_assets": 0,
                },
                "libraries": {"cublas": row},
            },
            seconds=0.01,
            candidate_library_ids=task.candidate_library_ids,
            triaged_library_ids=("cublas",),
            files_examined=1,
            bytes_examined=20,
            network_clone_count=1,
            network_fetch_count=2,
            network_materialized_bytes=123,
        )
        on_result(outcome)
        outcomes.append(outcome)
    return outcomes


def missing_scan_runner(
    _tasks, _libraries, _cache_root, on_result, **_kwargs
):
    del on_result
    return []


def duplicate_scan_runner(tasks, libraries, cache_root, on_result, **kwargs):
    outcomes = fake_scan_runner(
        tasks, libraries, cache_root, on_result, **kwargs
    )
    return outcomes + outcomes


def typed_error_scan_runner(
    tasks, libraries, cache_root, on_result, **kwargs
):
    del libraries, cache_root
    outcomes = []
    for task in tasks:
        if kwargs.get("before_task"):
            kwargs["before_task"](task)
        outcome = ScanOutcome(
            full_name=task.full_name,
            head_sha=task.head_sha,
            status="error",
            result=None,
            seconds=12.5,
            candidate_library_ids=task.candidate_library_ids,
            git_subprocess_count=7,
            network_fetch_count=2,
            error_code="repository_timeout",
            error_retryable=True,
            error="repository wall deadline exhausted",
        )
        on_result(outcome)
        outcomes.append(outcome)
    return outcomes


def skipped_large_scan_runner(tasks, libraries, cache_root, on_result, **kwargs):
    outcomes = fake_scan_runner(
        tasks, libraries, cache_root, on_result, **kwargs
    )
    for outcome in outcomes:
        outcome.skipped_large_files = 1
    return outcomes


def pruned_large_asset_scan_runner(
    tasks, libraries, cache_root, on_result, **kwargs
):
    pending = []
    outcomes = fake_scan_runner(
        tasks, libraries, cache_root, pending.append, **kwargs
    )
    for outcome in outcomes:
        outcome.pruned_large_assets = 1
        outcome.result["triage"]["pruned_large_assets"] = 1
        on_result(outcome)
    return outcomes


def clean_reject_scan_runner(tasks, libraries, cache_root, on_result, **_kwargs):
    del libraries, cache_root
    outcomes = []
    for task in tasks:
        if _kwargs.get("before_task"):
            _kwargs["before_task"](task)
        outcome = ScanOutcome(
            full_name=task.full_name,
            head_sha=task.head_sha,
            status="clean_reject",
            result={},
            seconds=0.01,
            candidate_library_ids=task.candidate_library_ids,
            triaged_library_ids=(),
            files_examined=1,
            bytes_examined=10,
        )
        on_result(outcome)
        outcomes.append(outcome)
    return outcomes


class FakeCitationPipeline:
    def refresh(self, *_args, **_kwargs):
        return types.SimpleNamespace(
            publishable=True,
            document={
                "generated_at": "2026-07-27T00:00:00Z",
                "source": "fixture",
                "method_version": "fixture",
                "libraries": {},
            },
        )


class AllFailedCitationPipeline:
    def refresh(self, *_args, **_kwargs):
        return types.SimpleNamespace(
            publishable=False,
            all_failed=True,
            used_last_good=False,
            document={
                "generated_at": "2026-07-27T00:00:00Z",
                "source": "fixture",
                "method_version": "fixture",
                "libraries": {},
                "coverage": {},
                "errors": {"all": ["synthetic outage"]},
            },
        )


class PipelineTests(unittest.TestCase):
    def test_notebook_issue_proof_masks_base64_but_not_authored_tokens(self):
        pattern = _encoded_token_pattern(("cublas", "cudss/header.h"))
        encoded_output = (
            b'{"outputs":[{"image/png":"'
            + b"A" * 300
            + b"cublas"
            + b"B" * 300
            + b'"}],"source":["ordinary code"]}'
        )
        proof = _verify_negative_blob(encoded_output, pattern)
        self.assertEqual([], proof["retention_token_hits"])
        for authored in (
            b'{"source":["cublas"]}',
            b'{"source":["\\u0063ublas"]}',
            b'{"source":["cudss\\/header.h"]}',
        ):
            with self.subTest(authored=authored):
                with self.assertRaisesRegex(
                    PipelineError, "contains a retention token"
                ):
                    _verify_negative_blob(authored, pattern)

    def test_notebook_issue_override_is_exact_blob_only(self):
        safe = b"exact malformed notebook bytes"
        unsafe = b"different malformed notebook bytes"
        with mock.patch(
            "collector.triage._notebook_might_affect_verdict",
            return_value=True,
        ) as original:
            with _exact_notebook_negatives((
                hashlib.sha256(safe).hexdigest(),
            )):
                self.assertFalse(
                    triage_module._notebook_might_affect_verdict(
                        safe, object()
                    )
                )
                self.assertTrue(
                    triage_module._notebook_might_affect_verdict(
                        unsafe, object()
                    )
                )
            original.assert_called_once_with(unsafe, mock.ANY)

    def test_blocked_lfs_override_is_exact_worktree_and_path_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            exact = cache / "worktrees" / "abcdef-task" / "src/use.py"
            other_path = (
                cache / "worktrees" / "abcdef-task" / "src/other.py"
            )
            other_repo = (
                cache / "worktrees" / "123456-task" / "src/use.py"
            )
            for path in (exact, other_path, other_repo):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"worktree")
            with _exact_blocked_worktree_reads(
                cache, {("abcdef", "src/use.py"): b"git-blob"}
            ):
                self.assertEqual(b"git-blob", exact.read_bytes())
                self.assertEqual(b"worktree", other_path.read_bytes())
                self.assertEqual(b"worktree", other_repo.read_bytes())
            self.assertEqual(b"worktree", exact.read_bytes())

    def test_notebook_issue_tolerant_extractor_ignores_corrupt_outputs(self):
        rendered = (
            '{"cells":[{"cell_type":"code","source":["ordinary()\\n"],'
            '"outputs":[{"text":"bad\\z control\u0006 cub"}]}],'
            '"metadata":{},"nbformat":4,"nbformat_minor":5}'
        )
        extracted = _tolerant_notebook_source_text(rendered)
        self.assertEqual(("ordinary()\n", 1, 1), extracted)

        authored = rendered.replace("ordinary()", "cublas()")
        extracted = _tolerant_notebook_source_text(authored)
        self.assertEqual(("cublas()\n", 1, 1), extracted)

    def test_compare_isolates_fixture_process_group_and_propagates_status(self):
        process = mock.Mock(pid=4321)
        process.wait.return_value = 7
        args = types.SimpleNamespace(
            repositories=(),
            repo_root="/fixture/repository",
        )
        with mock.patch.object(
            cli.subprocess, "Popen", return_value=process
        ) as popen:
            self.assertEqual(7, cli._compare(args))
        popen.assert_called_once_with(
            [
                cli.sys.executable,
                "-m",
                "unittest",
                "-v",
                "tests.test_req14_scanner",
                "tests.test_req14_portfolio",
            ],
            cwd="/fixture/repository",
            start_new_session=True,
        )
        process.wait.assert_called_once_with()

    def test_compare_interruption_reaps_isolated_fixture_process_group(self):
        process = mock.Mock(pid=4321)
        process.wait.side_effect = [KeyboardInterrupt(), 0]
        args = types.SimpleNamespace(
            repositories=(),
            repo_root="/fixture/repository",
        )
        with mock.patch.object(
            cli.subprocess, "Popen", return_value=process
        ), mock.patch.object(cli.os, "killpg") as killpg:
            with self.assertRaises(KeyboardInterrupt):
                cli._compare(args)
        killpg.assert_called_once_with(4321, cli.signal.SIGTERM)
        self.assertEqual(
            [mock.call(), mock.call(timeout=5)],
            process.wait.call_args_list,
        )

    def test_measured_mac_worker_defaults(self):
        self.assertEqual(6, RunBudgets.weekly().workers)
        self.assertEqual(14, RunBudgets.reconcile().workers)
        self.assertEqual(9 * 60, RunBudgets.weekly().repo_timeout_seconds)
        self.assertEqual(9 * 60, RunBudgets.reconcile().repo_timeout_seconds)
        self.assertLess(NETWORK_TASK_LEASE_SECONDS, 10 * 60)
        self.assertLess(WORK_TASK_LEASE_SECONDS, 10 * 60)
        self.assertEqual(2, PHASE8_ISSUE_RETRY_WORKERS)
        self.assertEqual(
            2,
            _issue_retry_workers(
                "phase8-cohort-a", RunBudgets.reconcile()
            ),
        )
        self.assertEqual(
            RunBudgets.weekly().workers,
            _issue_retry_workers(None, RunBudgets.weekly()),
        )

    def test_production_retry_wait_budget_is_mode_specific(self):
        with mock.patch(
            "collector.http_transport.resolve_github_token",
            return_value="public-token",
        ):
            weekly = CollectorPipeline.production(
                budgets=RunBudgets.weekly(),
                mode="refresh",
            )
            reconcile = CollectorPipeline.production(
                budgets=RunBudgets.reconcile(),
                mode="reconcile",
            )
        self.assertEqual(
            600,
            weekly._transport_metrics[
                "github_code_search"
            ].metrics_snapshot()["retry_seconds_budget"],
        )
        self.assertEqual(
            2 * 60 * 60,
            reconcile._transport_metrics[
                "github_code_search"
            ].metrics_snapshot()["retry_seconds_budget"],
        )
        with self.assertRaisesRegex(
            ValueError, "invalid production collector mode"
        ):
            CollectorPipeline.production(
                budgets=RunBudgets.weekly(),
                mode="invalid",
            )

    def test_production_fingerprint_manifest_is_pinned_and_source_sensitive(self):
        current = current_fingerprints()
        digest = hashlib.sha256(
            canonical_json(current.as_dict()).encode()
        ).hexdigest()
        self.assertEqual(
            "6c016aaf79261aabdba760f269448e8b97e6719810645472b26b1d92f28212bd",
            digest,
        )
        with mock.patch(
            "collector.planner._scanner_semantic_source_sha256",
            return_value="f" * 64,
        ):
            changed = current_fingerprints()
        self.assertEqual(set(current.libraries), set(changed.libraries))
        for library_id in current.libraries:
            before = current.libraries[library_id]
            after = changed.libraries[library_id]
            self.assertNotEqual(before.detector, after.detector)
            self.assertEqual(before.discovery, after.discovery)
            self.assertEqual(before.citation, after.citation)
            self.assertEqual(before.presentation, after.presentation)
            self.assertEqual(before.release, after.release)
        self.assertEqual(current.dating, changed.dating)
        self.assertEqual(current.ai, changed.ai)
        self.assertEqual(current.filters, changed.filters)
        self.assertEqual(current.aggregation, changed.aggregation)
        self.assertEqual(current.publication, changed.publication)

    def test_runtime_slo_profiles_and_warm_no_change_ceiling(self):
        weekly = RunBudgets.weekly()
        warm = _slo_profile("refresh", 0, weekly)
        self.assertEqual("warm_no_change", warm["class"])
        self.assertEqual(
            WARM_NO_CHANGE_TARGET_SECONDS, warm["target_seconds"]
        )
        self.assertEqual(
            WARM_NO_CHANGE_CEILING_SECONDS, warm["ceiling_seconds"]
        )
        normal = _slo_profile("refresh", 1, weekly)
        self.assertEqual("normal_weekly", normal["class"])
        self.assertEqual(2 * 3600, normal["target_seconds"])
        self.assertEqual(4 * 3600, normal["ceiling_seconds"])
        full = _slo_profile("reconcile", 30_000, RunBudgets.reconcile())
        self.assertEqual(24 * 3600, full["target_seconds"])
        self.assertEqual(36 * 3600, full["ceiling_seconds"])

        extended = dataclasses.replace(
            RunBudgets.reconcile(), max_wall_seconds=96 * 3600
        )
        cohort = _slo_profile(
            "reconcile", 38_000, extended, run_class="phase8-cohort-a"
        )
        self.assertEqual(24 * 3600, cohort["target_seconds"])
        self.assertEqual(96 * 3600, cohort["ceiling_seconds"])
        self.assertEqual(7 * 24 * 3600, PHASE8_MAX_OWNER_WALL_SECONDS)

        pipeline = CollectorPipeline(clock=lambda: 3601.0)
        with self.assertRaisesRegex(
            BudgetExceeded, "warm-no-change ceiling"
        ):
            pipeline._check_slo(
                mode="refresh",
                scans=0,
                started=0.0,
                budgets=weekly,
            )

        with mock.patch(
            "collector.pipeline._rss_usage_bytes",
            return_value={
                "self": weekly.max_rss_bytes,
                "children": 1,
                "combined_upper": weekly.max_rss_bytes + 1,
            },
        ):
            with self.assertRaisesRegex(BudgetExceeded, "RSS budget"):
                CollectorPipeline(clock=lambda: 0.0)._check_time(
                    0.0, weekly
                )

        def usage(kind):
            return types.SimpleNamespace(
                ru_maxrss=2 if kind == 0 else 3
            )

        with mock.patch("collector.pipeline.sys.platform", "darwin"), (
            mock.patch(
                "collector.pipeline.resource.getrusage",
                side_effect=usage,
            )
        ):
            self.assertEqual(
                {"self": 2, "children": 3, "combined_upper": 5},
                _rss_usage_bytes(),
            )
        with mock.patch("collector.pipeline.sys.platform", "linux"), (
            mock.patch(
                "collector.pipeline.resource.getrusage",
                side_effect=usage,
            )
        ):
            self.assertEqual(
                {
                    "self": 2 * 1024,
                    "children": 3 * 1024,
                    "combined_upper": 5 * 1024,
                },
                _rss_usage_bytes(),
            )

    def test_runtime_report_uses_exact_git_and_classification_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            result = pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self.budgets(),
            )
            report = result["report"]
            self.assertEqual(1, report["scan"]["clones"])
            self.assertEqual(2, report["scan"]["fetches"])
            self.assertEqual(
                123, report["scan"]["git_materialized_bytes"]
            )
            self.assertEqual(
                {
                    "confirmed": 1,
                    "bundled": 0,
                    "targeted": 0,
                    "rejected": 0,
                },
                report["scan"]["classifications"]["totals"],
            )
            self.assertIn(
                "target_remaining_seconds", report["slo"]
            )
            self.assertIn(
                "ceiling_remaining_seconds", report["slo"]
            )
            resources = report["resources"]
            self.assertEqual(
                resources["max_rss_self_bytes"]
                + resources["max_rss_children_bytes"],
                resources["max_rss_combined_upper_bytes"],
            )
            self.assertEqual(
                16 * 1024**3, resources["max_rss_budget_bytes"]
            )
            self.assertTrue(resources["within_rss_budget"])
            visibility = report["api"]["final_visibility"]
            self.assertEqual(1, visibility["repository_count"])
            self.assertEqual(1, visibility["graphql_requests"])
            self.assertEqual(1, visibility["graphql_points"])
            self.assertEqual(2, report["api"]["graphql_requests"])
            self.assertEqual(2, report["api"]["graphql_points"])
            self.assertLessEqual(
                visibility["oldest_attestation_age_seconds"],
                visibility["max_attestation_age_seconds"],
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                stage = state.connection.execute(
                    """
                    SELECT counters_json, metrics_json FROM stages
                    WHERE run_id=? AND stage='scan'
                    """,
                    (result["run_id"],),
                ).fetchone()
            counters = json.loads(stage["counters_json"])
            metrics = json.loads(stage["metrics_json"])
            self.assertEqual(1, counters["clones"])
            self.assertEqual(2, counters["fetches"])
            self.assertEqual(
                1, counters["classifications"]["confirmed"]
            )
            self.assertEqual(123, metrics["git_materialized_bytes"])
            self.assertEqual(
                1,
                metrics["classifications"]["by_library"]["cublas"][
                    "confirmed"
                ],
            )

    def test_classification_inventory_counts_cross_library_rejects(self):
        outcome = ScanOutcome(
            full_name="public/example",
            head_sha="a" * 40,
            status="match",
            result={
                "libraries": {
                    "confirmed-lib": {"classification": "confirmed"},
                    "bundled-lib": {"classification": "bundled"},
                    "targeted-lib": {"classification": "targeted"},
                }
            },
            seconds=0.01,
            candidate_library_ids=(
                "confirmed-lib",
                "bundled-lib",
            ),
            triaged_library_ids=(
                "targeted-lib",
                "rejected-lib",
            ),
        )
        inventory = _scan_classification_inventory((outcome,))
        self.assertEqual(
            {
                "confirmed": 1,
                "bundled": 1,
                "targeted": 1,
                "rejected": 1,
            },
            inventory["totals"],
        )
        self.assertEqual(
            1, inventory["by_library"]["rejected-lib"]["rejected"]
        )

    @staticmethod
    def budgets(
        *,
        sourcegraph_requests=10,
        github_requests=100,
        scans=10,
    ):
        return RunBudgets(
            max_wall_seconds=300,
            max_scan_repositories=scans,
            max_sourcegraph_requests=sourcegraph_requests,
            max_github_search_requests=github_requests,
            max_graphql_points=100,
            min_graphql_remaining=50,
            max_fetches=scans,
            workers=1,
            cache_target_bytes=10**8,
            cache_hard_bytes=2 * 10**8,
        )

    @staticmethod
    def cohort_contract(*selected, metadata_batch_size=1):
        selected_ids = sorted(selected)
        active_ids = {library["id"] for library in LIBRARIES}
        historical_scan_usage = {
            "version": 1,
            "predecessor_run_id": "fixture-predecessor",
            "predecessor_plan_sha256": "a" * 64,
            "predecessor_lineage_sha256": "b" * 64,
            "attempt_count": 0,
            "exact_attempt_count": 0,
            "conservative_attempt_count": 0,
            "timing_known_attempt_count": 0,
            "timing_unknown_attempt_count": 0,
            "usage": {
                "seconds": 0.0,
                "current_tree_triage_seconds": 0.0,
                "history_dating_seconds": 0.0,
                "analysis_seconds": 0.0,
                "git_subprocess_count": 0,
                "git_subprocess_unknown_attempt_count": 0,
                "network_clone_count": 0,
                "network_clone_unknown_attempt_count": 0,
                "network_fetch_count": 0,
                "network_fetch_unknown_attempt_count": 0,
                "network_materialized_bytes": 0,
            },
            "proof_rows": [],
            "proof_rows_sha256": hashlib.sha256(
                canonical_json([]).encode("utf-8")
            ).hexdigest(),
        }
        historical_scan_usage["contract_sha256"] = hashlib.sha256(
            canonical_json(historical_scan_usage).encode("utf-8")
        ).hexdigest()
        return {
            "mode": "reconcile",
            "run_class": "phase8-cohort-a",
            "release_scope": "partial-portfolio",
            "release_label": "Phase 8 Cohort A",
            "selected_library_ids": selected_ids,
            "excluded_library_ids": sorted(
                active_ids - set(selected_ids)
            ),
            "metadata_batch_size": metadata_batch_size,
            "network_task_source_sha256": (
                _network_task_source_sha256()
            ),
            "historical_network_request_attempts": {
                "github-code-search": 0,
                "sourcegraph": 0,
            },
            "historical_scan_usage": historical_scan_usage,
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

    def test_cold_reconcile_plan_and_command_require_explicit_confirmation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            plan = build_plan(
                mode="reconcile",
                state_path=root / ".state/collector.sqlite3",
                data_dir=root / "data",
            )
            self.assertTrue(plan.cold_state)
            self.assertTrue(plan.requires_full_confirmation)
            self.assertEqual(30_000, plan.unknown_repository_size_count)
            self.assertEqual(
                30_000 * 50 * 1024 * 1024,
                plan.estimated_network_bytes["git_transfer_upper_estimate"],
            )
            expected_packs = sum(
                len(query_packs(library)) for library in LIBRARIES
            )
            self.assertEqual(
                expected_packs, plan.estimated_sourcegraph_requests
            )
            self.assertEqual(
                expected_packs,
                plan.estimated_github_search_requests_floor,
            )
            weekly_view = build_plan(
                mode="refresh",
                state_path=root / ".state/collector.sqlite3",
                data_dir=root / "data",
            )
            self.assertEqual(
                plan.estimated_wall_minutes,
                weekly_view.estimated_wall_minutes,
            )
            pipeline = CollectorPipeline(repo_root=root)
            with self.assertRaises(PipelineError):
                pipeline.run(mode="reconcile", confirm_full=False)
            self.assertFalse((root / ".state").exists())

    def test_warm_30k_plan_uses_local_reuse_not_fixed_churn_guess(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            state_path = root / ".state/collector.sqlite3"
            cold = build_plan(
                mode="refresh",
                state_path=state_path,
                data_dir=root / "data",
            )
            with StateDB(state_path) as state:
                state.create_run(
                    "last-good",
                    mode="refresh",
                    fingerprints=cold.fingerprints.as_dict(),
                    status="running",
                )
                state.finish_run("last-good", status="complete")
            base_counts = {
                "known_repositories": 30_000,
                "active_candidates": 45_000,
                "reusable_scan_results": 45_000,
                "nonreusable_candidate_repositories": 0,
                "analysis_only_repositories": 0,
                "locally_planned_scan_repositories": 0,
                "positive_repositories": 18_000,
                "legacy_published_repositories": 0,
            }
            with mock.patch(
                "collector.planner._local_counts",
                return_value=base_counts,
            ):
                no_change = build_plan(
                    mode="refresh",
                    state_path=state_path,
                    data_dir=root / "data",
                )
            self.assertFalse(no_change.cold_state)
            self.assertEqual(0, no_change.estimated_scans)
            self.assertFalse(no_change.requires_full_confirmation)
            self.assertEqual([], list(no_change.reasons))

            changed_counts = {
                **base_counts,
                "reusable_scan_results": 42_499,
                "nonreusable_candidate_repositories": 2_501,
                "locally_planned_scan_repositories": 2_501,
            }
            with mock.patch(
                "collector.planner._local_counts",
                return_value=changed_counts,
            ):
                changed = build_plan(
                    mode="refresh",
                    state_path=state_path,
                    data_dir=root / "data",
                )
            self.assertEqual(2_501, changed.estimated_scans)
            self.assertTrue(changed.requires_full_confirmation)
            self.assertTrue(
                any("(2501 > 2000)" in reason for reason in changed.reasons)
            )

    def test_warm_plan_counts_only_current_nonreusable_repository_work(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            state_path = root / ".state/collector.sqlite3"
            library = next(
                item for item in LIBRARIES if item["id"] == "cublas"
            )
            cold = build_plan(
                mode="refresh",
                state_path=state_path,
                data_dir=root / "data",
                libraries=[library],
            )
            values = cold.fingerprints.libraries["cublas"]
            fingerprints = {
                **values.as_dict(),
                "dating": cold.fingerprints.dating,
                "aggregation": cold.fingerprints.aggregation,
            }
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog={"name": "cuBLAS"},
                    fingerprints=fingerprints,
                )
                for ordinal in range(2):
                    node_id = "R_%d" % ordinal
                    head = str(ordinal + 1) * 40
                    state.upsert_repository({
                        "node_id": node_id,
                        "full_name": "public/repo-%d" % ordinal,
                        "visibility": "public",
                        "head_sha": head,
                    })
                    state.add_candidate(
                        repository_id=node_id,
                        library_id="cublas",
                        source="sourcegraph",
                        query_fp="fixture",
                        coverage_epoch="fixture",
                    )
                    if ordinal == 0:
                        state.record_scan_result(
                            repository_id=node_id,
                            library_id="cublas",
                            head_sha=head,
                            detector_fp=values.detector,
                            classification="rejected",
                            status="clean",
                        )
                state.create_run(
                    "last-good",
                    mode="refresh",
                    fingerprints=cold.fingerprints.as_dict(),
                    status="running",
                )
                state.finish_run("last-good", status="complete")
            warm = build_plan(
                mode="refresh",
                state_path=state_path,
                data_dir=root / "data",
                libraries=[library],
            )
            self.assertEqual(
                1, warm.local_counts["nonreusable_candidate_repositories"]
            )
            self.assertEqual(
                1, warm.local_counts["locally_planned_scan_repositories"]
            )
            self.assertEqual(1, warm.estimated_scans)

    def test_plan_reports_network_bytes_and_public_outliers_from_local_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            state_path = root / ".state/collector.sqlite3"
            library = next(lib for lib in LIBRARIES if lib["id"] == "cublas")
            cold = build_plan(
                mode="refresh",
                state_path=state_path,
                data_dir=root / "data",
                libraries=[library],
            )
            library_fp = cold.fingerprints.libraries["cublas"]
            state_fingerprints = {
                **library_fp.as_dict(),
                "dating": cold.fingerprints.dating,
                "aggregation": cold.fingerprints.aggregation,
            }
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog={"name": "cuBLAS"},
                    fingerprints=state_fingerprints,
                )
                for ordinal in range(10):
                    node_id = f"R_public_{ordinal}"
                    state.upsert_repository({
                        "node_id": node_id,
                        "full_name": f"public/repo-{ordinal}",
                        "visibility": "public",
                        "head_sha": str(ordinal) * 40,
                        "metadata": {
                            "disk_usage_kb": 10_000 - ordinal * 100,
                        },
                    })
                    state.add_candidate(
                        repository_id=node_id,
                        library_id="cublas",
                        source="sourcegraph",
                        query_fp="query-fingerprint",
                        coverage_epoch="fixture",
                        signal="cublas_v2.h",
                    )
                state.create_run(
                    "last-good",
                    mode="refresh",
                    fingerprints=cold.fingerprints.as_dict(),
                    status="running",
                )
                state.finish_run("last-good", status="complete")

            plan = build_plan(
                mode="refresh",
                state_path=state_path,
                data_dir=root / "data",
                libraries=[library],
            )
            document = plan.to_dict()
            network = document["estimates"]["network_bytes"]
            self.assertEqual(
                network["total"],
                sum(value for key, value in network.items() if key != "total"),
            )
            self.assertGreater(network["git_transfer_upper_estimate"], 0)
            self.assertEqual(
                "public/repo-0",
                document["outliers"]["repositories"][0]["full_name"],
            )
            self.assertEqual(
                10,
                document["outliers"]["observed_queries"][0][
                    "observed_active_candidates"
                ],
            )
            self.assertTrue(document["outliers"]["planned_query_groups"])
            self.assertTrue(document["estimate_assumptions"])
            self.assertEqual(
                0,
                document["estimates"]["repositories_with_unknown_size"],
            )

    def test_plan_reports_unknown_repository_sizes_without_conflating_zero(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            state_path = root / ".state/collector.sqlite3"
            with StateDB(state_path) as state:
                for node_id, name, metadata in (
                    ("R_unknown", "public/unknown", {}),
                    ("R_zero", "public/known-zero", {"disk_usage_kb": 0}),
                    ("R_sized", "public/sized", {"disk_usage_kb": 12}),
                ):
                    state.upsert_repository({
                        "node_id": node_id,
                        "full_name": name,
                        "visibility": "public",
                        "head_sha": node_id[-1] * 40,
                        "metadata": metadata,
                    })

            document = build_plan(
                mode="refresh",
                state_path=state_path,
                data_dir=root / "data",
                libraries=[
                    next(
                        library
                        for library in LIBRARIES
                        if library["id"] == "cublas"
                    )
                ],
            ).to_dict()
            self.assertEqual(
                1,
                document["estimates"]["repositories_with_unknown_size"],
            )
            rows = {
                row["full_name"]: row
                for row in document["outliers"]["repositories"]
            }
            self.assertIsNone(
                rows["public/unknown"][
                    "estimated_git_transfer_bytes_upper_bound"
                ]
            )
            self.assertEqual(
                "size unavailable", rows["public/unknown"]["size_basis"]
            )
            self.assertEqual(
                0,
                rows["public/known-zero"][
                    "estimated_git_transfer_bytes_upper_bound"
                ],
            )
            self.assertEqual(
                "GitHub diskUsage metadata",
                rows["public/known-zero"]["size_basis"],
            )

    def test_cli_plan_separates_cumulative_git_work_from_retained_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            output = io.StringIO()
            with mock.patch("sys.stdout", output):
                exit_code = cli.main([
                    "--repo-root", str(root),
                    "plan", "--json",
                ])
            self.assertEqual(0, exit_code)
            disk = json.loads(output.getvalue())["local_disk"]
            self.assertGreater(
                disk["estimated_cumulative_git_materialization_bytes"],
                disk["retained_cache_hard_bytes"],
            )
            self.assertEqual(
                disk["retained_cache_hard_bytes"],
                disk["retained_cache_growth_upper_bytes"],
            )
            self.assertIn("hard_cache_plus_margin_fits", disk)

    def test_cli_plan_reports_selected_hard_budgets(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            output = io.StringIO()
            with mock.patch("sys.stdout", output):
                exit_code = cli.main([
                    "--repo-root", str(root),
                    "plan",
                    "--mode", "reconcile",
                    "--workers", "4",
                    "--max-scan-repositories", "123",
                    "--json",
                ])
            self.assertEqual(0, exit_code)
            document = json.loads(output.getvalue())
            budgets = document["budgets"]
            self.assertEqual(4, budgets["workers"])
            self.assertEqual(123, budgets["max_scan_repositories"])
            self.assertEqual(
                RunBudgets.reconcile().max_rss_bytes,
                budgets["max_rss_bytes"],
            )
            self.assertEqual(
                RunBudgets.reconcile().cache_hard_bytes,
                document["local_disk"]["retained_cache_hard_bytes"],
            )

    def test_citations_merge_missing_library_from_v1_and_wire_budgets(self):
        class PartialCitations:
            def __init__(self):
                self.kwargs = None

            def refresh(self, *_args, **kwargs):
                self.kwargs = kwargs
                return types.SimpleNamespace(
                    publishable=True,
                    document={
                        "generated_at": "2026-07-27T00:00:00Z",
                        "source": "fixture",
                        "method_version": "fixture",
                        "stale": False,
                        "coverage": {"cublas": {"complete": True}},
                        "errors": {},
                        "libraries": {
                            "cublas": {
                                "name": "fresh cuBLAS",
                                "total": 2,
                                "stale": False,
                                "errors": [],
                                "coverage": {"complete": True},
                            }
                        },
                    },
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            (root / "data/citations.json").write_text(
                json.dumps(
                    {
                        "source": "V1 fixture",
                        "libraries": {
                            "cublas": {"name": "old cuBLAS", "total": 1},
                            "cudnn": {"name": "old cuDNN", "total": 9},
                        },
                    }
                )
            )
            partial = PartialCitations()
            pipeline = CollectorPipeline(
                repo_root=root,
                citation_pipeline=partial,
            )
            budgets = self.budgets()
            with StateDB(root / ".state/collector.sqlite3") as state:
                document = pipeline._citations(
                    state, {"repos": []}, budgets
                )
            self.assertEqual("fresh cuBLAS", document["libraries"]["cublas"]["name"])
            carried = document["libraries"]["cudnn"]
            self.assertEqual(9, carried["total"])
            self.assertTrue(carried["stale"])
            self.assertTrue(carried["coverage"]["carried_forward"])
            self.assertEqual(
                budgets.max_openalex_requests,
                partial.kwargs["max_openalex_requests"],
            )
            self.assertEqual(
                budgets.max_citation_source_extractions,
                partial.kwargs["max_source_extractions"],
            )

    def test_first_release_refuses_all_failed_citations_without_last_good(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            pipeline = CollectorPipeline(
                repo_root=root,
                citation_pipeline=AllFailedCitationPipeline(),
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                with self.assertRaisesRegex(
                    PipelineError, "all citation lanes failed"
                ):
                    pipeline._citations(
                        state,
                        {"repos": []},
                        self.budgets(),
                    )

    def test_cli_exposes_explicit_citation_budget_overrides(self):
        wall = build_parser().parse_args([
            "run-wall-extend",
            "--run-id",
            "cohort",
            "--predecessor-source-ref",
            "420a8fa",
        ])
        self.assertEqual(7 * 24, wall.max_wall_hours)
        args = build_parser().parse_args(
            [
                "refresh",
                "--max-openalex-requests",
                "321",
                "--max-citation-source-extractions",
                "123",
            ]
        )
        budgets = _budget(args, "refresh")
        self.assertEqual(321, budgets.max_openalex_requests)
        self.assertEqual(123, budgets.max_citation_source_extractions)
        args = build_parser().parse_args(
            ["refresh", "--max-openalex-requests", "-1"]
        )
        with self.assertRaisesRegex(ValueError, "cannot be negative"):
            _budget(args, "refresh")
        for flag, value, message in (
            ("--max-wall-seconds", "0", "must be positive"),
            ("--max-scan-repositories", "-1", "cannot be negative"),
            ("--workers", "0", "must be positive"),
            ("--repo-timeout-seconds", "0", "must be positive"),
        ):
            with self.subTest(flag=flag):
                parsed = build_parser().parse_args(
                    ["refresh", flag, value]
                )
                with self.assertRaisesRegex(ValueError, message):
                    _budget(parsed, "refresh")
        parsed = build_parser().parse_args([
            "refresh",
            "--cache-target-bytes",
            "20",
            "--cache-hard-bytes",
            "10",
        ])
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            _budget(parsed, "refresh")

    def test_validate_resolves_data_under_repo_root_from_other_cwd(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as cwd:
            root = Path(td)
            expected = (root / "relative-data/v2").resolve()
            args = types.SimpleNamespace(
                repo_root=str(root),
                data="relative-data",
            )
            prior = Path.cwd()
            try:
                os.chdir(cwd)
                with mock.patch(
                    "collector.cli.validate_v2", return_value=[]
                ) as validate:
                    self.assertEqual(0, _validate(args))
            finally:
                os.chdir(prior)
            validate.assert_called_once_with(expected)

    def test_cold_weekly_refuses_before_state_or_network(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            pipeline = CollectorPipeline(repo_root=root)
            with self.assertRaises(BudgetExceeded):
                pipeline.run(mode="refresh", budgets=RunBudgets.weekly())
            self.assertFalse((root / ".state").exists())

    def test_incomplete_required_discovery_fails_before_later_network_lanes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            sourcegraph = FakeDiscovery("sourcegraph")
            github = IncompleteDiscovery("github-code-search")
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=sourcegraph,
                github_search=github,
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            with self.assertRaisesRegex(
                PipelineError,
                "github-code-search discovery coverage incomplete",
            ):
                pipeline.run(
                    mode="reconcile",
                    confirm_full=True,
                    budgets=RunBudgets.reconcile(),
                )
            self.assertEqual(1, sourcegraph.calls)
            self.assertEqual(1, github.calls)
            with StateDB(root / ".state/collector.sqlite3") as state:
                task_states = state.connection.execute(
                    """
                    SELECT status, COUNT(*) AS count
                    FROM tasks
                    WHERE stage='discovery-query'
                    GROUP BY status
                    """
                ).fetchall()
                self.assertEqual(
                    {"complete": 1, "pending": 257},
                    {
                        row["status"]: row["count"]
                        for row in task_states
                    },
                )
                coverage = state.connection.execute(
                    """
                    SELECT complete, gaps_json
                    FROM discovery_coverage
                    WHERE source='github-code-search'
                    """
                ).fetchone()
                self.assertEqual(0, coverage["complete"])
                self.assertIn("unexpected_skip", coverage["gaps_json"])

    def test_weekly_rotation_publishes_prior_fresh_github_certificate(self):
        cublas = next(lib for lib in LIBRARIES if lib["id"] == "cublas")
        pack = query_packs(cublas)[0]
        query_fp = _github_query_fp(pack)
        observed = "2026-07-13T00:00:00Z"
        certificate = {
            "source": "github-code-search",
            "library_id": "cublas",
            "query_fingerprint": query_fp,
            "epoch_started_at": observed,
            "epoch_completed_at": observed,
            "complete": True,
            "terminal": True,
            "observations_count": 3,
            "quarantined_count": 0,
            "partitions": [],
            "intentional_skips": [],
            "gaps": [],
            "source_lag_max_seconds": 0,
            "metrics": {},
        }
        with tempfile.TemporaryDirectory() as td:
            with StateDB(
                Path(td) / "state.sqlite3",
                now=lambda: observed,
            ) as state:
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
                state.create_run("prior", mode="refresh", status="running")
                state.record_discovery_coverage(
                    run_id="prior",
                    library_id="cublas",
                    source="github-code-search",
                    query_fp=query_fp,
                    partition_key="all",
                    complete=True,
                    result_count=3,
                    certificate=certificate,
                )
                state.finish_run("prior", status="complete")
                current = [{
                    **certificate,
                    "source": "sourcegraph",
                    "query_fingerprint": "sourcegraph-current",
                    "epoch_started_at": "2026-07-27T00:00:00Z",
                    "epoch_completed_at": "2026-07-27T00:00:00Z",
                }]
                merged = _carry_forward_coverage_certificates(
                    state,
                    [cublas],
                    current,
                    now=datetime.datetime(
                        2026, 7, 27, tzinfo=datetime.timezone.utc
                    ),
                )
        github = next(
            item for item in merged
            if item["source"] == "github-code-search"
        )
        self.assertTrue(github["carried_forward"])
        self.assertFalse(github["stale"])
        stats = _discovery_stats([cublas], {"certificates": merged})["cublas"]
        self.assertTrue(stats["carried_forward"])
        self.assertFalse(stats["stale"])
        self.assertEqual(observed, stats["sources"]["github-code-search"]["as_of"])

    def test_public_discovery_stats_exclude_incomplete_advisory_certificate(self):
        cublas = next(lib for lib in LIBRARIES if lib["id"] == "cublas")
        complete = {
            "source": "github-code-search",
            "library_id": "cublas",
            "query_fingerprint": "github-complete",
            "epoch_started_at": "2026-08-01T00:00:00Z",
            "epoch_completed_at": "2026-08-01T00:01:00Z",
            "complete": True,
            "terminal": True,
            "observations_count": 1,
            "quarantined_count": 0,
            "gaps": [],
            "source_lag_max_seconds": 0,
        }
        incomplete = {
            **complete,
            "source": "sourcegraph",
            "query_fingerprint": "sourcegraph-incomplete",
            "complete": False,
            "gaps": [{"reason": "server_timeout"}],
        }
        stats = _discovery_stats(
            [cublas], {"certificates": [incomplete, complete]}
        )["cublas"]
        self.assertEqual([complete], stats["certificates"])
        self.assertEqual({"github-code-search"}, set(stats["sources"]))
        self.assertEqual([], stats["coverage_gaps"])

    def test_confirmed_component_promotes_weaker_parent_family_row(self):
        repos = [{
            "full_name": "public/family-precedence",
            "earliest_integration": None,
            "libraries": [
                {
                    "library_id": "cublas",
                    "classification": "targeted",
                    "first_integration": None,
                    "first_integration_commit": "",
                    "operators": ["cublas"],
                },
                {
                    "library_id": "cublaslt",
                    "classification": "confirmed",
                    "first_integration": "2025-04-03",
                    "first_integration_commit": "component-sha",
                    "operators": ["cublasLtMatmul"],
                },
            ],
        }]
        _materialize_family_rollup_entries(repos)
        parent = next(
            entry for entry in repos[0]["libraries"]
            if entry["library_id"] == "cublas"
        )
        self.assertEqual("confirmed", parent["classification"])
        self.assertEqual(
            "targeted", parent["direct_parent_classification"]
        )
        self.assertTrue(parent["derived_family_rollup"])
        self.assertTrue(parent["family_rollup"])
        self.assertEqual(["cublaslt"], parent["component_ids"])
        self.assertEqual("2025-04-03", parent["first_integration"])
        self.assertEqual("2025-04-03", repos[0]["earliest_integration"])

        _restore_direct_parent_entries(repos)
        parent = next(
            entry for entry in repos[0]["libraries"]
            if entry["library_id"] == "cublas"
        )
        self.assertEqual("targeted", parent["classification"])
        self.assertIsNone(parent["first_integration"])
        self.assertNotIn("family_rollup", parent)
        self.assertNotIn("component_ids", parent)
        self.assertEqual("2025-04-03", repos[0]["earliest_integration"])

    def test_discovery_specs_use_prefix_and_import_shaped_anchors(self):
        by_id = {lib["id"]: lib for lib in LIBRARIES}
        for library_id, prefix in (
            ("cutlass", "cutlass/"),
            ("thrust", "thrust/"),
            ("cub", "cub/"),
            ("nvcomp", "nvcomp/"),
        ):
            specs = signal_specs(by_id[library_id])
            self.assertIn(prefix, {spec.anchor for spec in specs})
            self.assertTrue(any(
                prefix in spec.github_query
                and spec.signal_id.startswith("header-prefix-")
                for spec in specs
            ))
        warp_queries = {
            spec.github_query for spec in signal_specs(by_id["warp"])
        }
        self.assertIn('"import warp"', warp_queries)
        self.assertIn('"from warp"', warp_queries)
        self.assertNotIn('"warp"', warp_queries)
        nvpl_specs = signal_specs(by_id["nvpl"])
        self.assertTrue(any(
            spec.anchor == "nvpl_"
            and spec.signal_id.startswith("header-prefix-")
            for spec in nvpl_specs
        ))
        self.assertNotIn(
            "nvpl",
            {
                spec.anchor
                for spec in nvpl_specs
                if spec.signal_id.startswith("broad-")
            },
        )

    def test_query_packs_reduce_lanes_without_losing_signal_membership(self):
        original = [
            spec
            for library in LIBRARIES
            for spec in signal_specs(library)
        ]
        packed = [
            pack
            for library in LIBRARIES
            for pack in query_packs(library)
        ]
        self.assertEqual(181, len(original))
        self.assertEqual(129, len(packed))
        self.assertEqual(
            sorted(
                (spec.library_id, spec.signal_id)
                for spec in original
            ),
            sorted(
                (pack.library_id, signal_id)
                for pack in packed
                for signal_id in pack.member_signal_ids
            ),
        )
        for pack in packed:
            self.assertLessEqual(len(pack.member_signal_ids), 6)
            self.assertLessEqual(len(pack.github_query), 180)
            self.assertEqual(
                len(pack.member_signal_ids),
                len(pack.anchors),
            )
            if len(pack.member_signal_ids) > 1:
                self.assertIn(" OR ", pack.github_query)
                self.assertIn(" OR ", pack.sourcegraph_query)
                self.assertNotEqual("broad", pack.kind)
            self.assertFalse(pack.github_query.startswith("("))
            self.assertFalse(pack.github_query.endswith(")"))
            self.assertEqual(
                2 * len(pack.member_signal_ids),
                pack.github_query.count('"'),
            )
        by_id = {lib["id"]: lib for lib in LIBRARIES}
        video = query_packs(by_id["video-codec-sdk"])[0]
        self.assertEqual(
            '"nvEncodeAPI.h" OR "nvcuvid.h" OR "cuviddec.h"',
            video.github_query,
        )
        self.assertNotIn("(", video.github_query)
        nvimagecodec = query_packs(by_id["nvimagecodec"])[0]
        self.assertEqual(
            '"import nvidia.nvimgcodec" OR "from nvidia.nvimgcodec"',
            nvimagecodec.github_query,
        )
        self.assertTrue(nvimagecodec.sourcegraph_query.startswith("("))
        self.assertIn(" OR ", nvimagecodec.sourcegraph_query)

    def test_query_pack_fingerprints_are_source_and_membership_specific(self):
        cublas = next(lib for lib in LIBRARIES if lib["id"] == "cublas")
        pack = query_packs(cublas)[0]
        self.assertEqual(pack, query_packs(cublas)[0])
        self.assertNotEqual(
            github_query_fingerprint(pack),
            sourcegraph_query_fingerprint(pack),
        )
        changed = dataclasses.replace(
            pack,
            member_signal_ids=("replacement-signal",) + pack.member_signal_ids[1:],
        )
        self.assertNotEqual(
            github_query_fingerprint(pack),
            github_query_fingerprint(changed),
        )

    def test_retirement_requires_each_expected_pack_not_merely_lane_count(self):
        cublas = next(lib for lib in LIBRARIES if lib["id"] == "cublas")
        packs = query_packs(cublas)
        now = "2026-07-27T00:00:00Z"

        def certificate(source, query_fingerprint):
            return {
                "source": source,
                "library_id": "cublas",
                "query_fingerprint": query_fingerprint,
                "epoch_completed_at": now,
                "complete": True,
                "terminal": True,
            }

        wrong = {
            "certificates": [
                certificate("sourcegraph", "wrong-sourcegraph-pack"),
                certificate("github-code-search", "wrong-github-pack"),
            ]
        }
        self.assertEqual(
            set(),
            _retirement_eligible_library_ids([cublas], wrong),
        )
        exact = {
            "certificates": [
                certificate(
                    "github-code-search",
                    github_query_fingerprint(pack),
                )
                for pack in packs
            ]
        }
        self.assertEqual(
            {"cublas"},
            _retirement_eligible_library_ids([cublas], exact),
        )

    def test_targeted_end_to_end_is_public_atomic_and_valid(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            sourcegraph = FakeDiscovery("sourcegraph")
            github_search = FakeDiscovery("github-code-search")
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=sourcegraph,
                github_search=github_search,
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            budgets = self.budgets()
            result = pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=budgets,
            )
            self.assertEqual(2, sourcegraph.calls)
            self.assertEqual(2, github_search.calls)
            self.assertEqual(result["scanned"], 1)
            with StateDB(root / ".state/collector.sqlite3") as state:
                discovery_stage = state.connection.execute(
                    """
                    SELECT metrics_json FROM stages
                    WHERE run_id=? AND stage='discovery'
                    """,
                    (result["run_id"],),
                ).fetchone()
                discovery_metrics = json.loads(
                    discovery_stage["metrics_json"]
                )
                self.assertEqual(
                    {
                        "declared": 3,
                        "sourcegraph_packs": 2,
                        "github_packs": 2,
                        "github_requests": 2,
                        "saved": 1,
                    },
                    {
                        "declared": discovery_metrics[
                            "declared_signal_lanes"
                        ],
                        "sourcegraph_packs": discovery_metrics[
                            "sourcegraph_query_packs"
                        ],
                        "github_packs": discovery_metrics[
                            "github_query_packs"
                        ],
                        "github_requests": discovery_metrics[
                            "github_search_requests"
                        ],
                        "saved": discovery_metrics[
                            "packed_sourcegraph_lanes_saved"
                        ],
                    },
                )
                library_rows = state.connection.execute(
                    "SELECT library_id, active FROM libraries"
                ).fetchall()
                executable_ids = {lib["id"] for lib in LIBRARIES}
                self.assertEqual(len(CATALOG), len(library_rows))
                self.assertEqual(
                    executable_ids,
                    {
                        row["library_id"]
                        for row in library_rows
                        if row["active"]
                    },
                )
                self.assertEqual(
                    {item["id"] for item in CATALOG} - executable_ids,
                    {
                        row["library_id"]
                        for row in library_rows
                        if not row["active"]
                    },
                )
                self.assertEqual(
                    len(CATALOG_EVENTS),
                    state.connection.execute(
                        "SELECT COUNT(*) FROM catalog_events"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0,
                    state.connection.execute(
                        """
                        SELECT COUNT(*) FROM candidates c
                        JOIN libraries l ON l.library_id=c.library_id
                        WHERE l.active=0
                        """
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0,
                    state.connection.execute(
                        """
                        SELECT COUNT(*) FROM tasks t
                        JOIN libraries l ON l.library_id=t.library_id
                        WHERE l.active=0
                        """
                    ).fetchone()[0],
                )
            manifest_path = root / "data/v2/manifest.json"
            self.assertTrue(manifest_path.exists())
            self.assertEqual(validate_v2(root / "data/v2"), [])
            manifest = json.loads(manifest_path.read_text())
            self.assertLess(manifest_path.stat().st_size, 250 * 1024)
            cublas = next(item for item in manifest["libraries"] if item["id"] == "cublas")
            self.assertEqual(cublas["confirmed_count"], 1)
            self.assertEqual(cublas["bundled_count"], None)
            self.assertEqual(cublas["targeted_count"], 0)
            pending = next(
                item for item in manifest["libraries"] if item["id"] == "cuda-math-api"
            )
            self.assertEqual(pending["confirmed_count"], None)
            for unselected_id in ("cudnn", "warp", "cufftdx"):
                unselected = next(
                    item for item in manifest["libraries"]
                    if item["id"] == unselected_id
                )
                self.assertEqual("not_collected", unselected["collection_status"])
                self.assertEqual(None, unselected["confirmed_count"])
                self.assertEqual(None, unselected["bundled_count"])
                self.assertEqual(None, unselected["targeted_count"])
            checkpoint = root / "data/state-checkpoint/manifest.json"
            self.assertTrue(checkpoint.exists())
            checkpoint_text = "\n".join(
                path.read_text(errors="ignore")
                for path in (root / "data/state-checkpoint").rglob("*")
                if path.is_file()
            )
            self.assertNotIn("PRIVATE", checkpoint_text)
            with StateDB(root / "restored.sqlite3") as restored:
                restored.import_checkpoint(checkpoint.parent)
                run_row = restored.connection.execute(
                    "SELECT status FROM runs WHERE run_id=?",
                    (result["run_id"],),
                ).fetchone()
                stage_row = restored.connection.execute(
                    """
                    SELECT status FROM stages
                    WHERE run_id=? AND stage='publication'
                    """,
                    (result["run_id"],),
                ).fetchone()
                self.assertEqual(run_row["status"], "complete")
                self.assertEqual(stage_row["status"], "complete")
                self.assertEqual(
                    len(CATALOG),
                    restored.connection.execute(
                        "SELECT COUNT(*) FROM libraries"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    len(CATALOG_EVENTS),
                    restored.connection.execute(
                        "SELECT COUNT(*) FROM catalog_events"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    len(CATALOG) - len(LIBRARIES),
                    restored.connection.execute(
                        "SELECT COUNT(*) FROM libraries WHERE active=0"
                    ).fetchone()[0],
                )

            quality = json.loads(
                (
                    root
                    / "data/v2"
                    / manifest["quality"]["path"]
                ).read_text()
            )
            cublas_quality = quality["discovery_stats"]["cublas"]
            self.assertEqual(
                cublas_quality["evidence_kind"], "certificates"
            )
            self.assertEqual(
                {item["source"] for item in cublas_quality["certificates"]},
                {"sourcegraph", "github-code-search"},
            )
            self.assertEqual(4, len(cublas_quality["certificates"]))
            for certificate in cublas_quality["certificates"]:
                metrics = certificate["metrics"]
                if metrics["query_pack_kind"] == "header":
                    self.assertEqual(2, metrics["member_count"])
                    self.assertEqual(
                        "header-00,header-01",
                        metrics["member_signal_ids"],
                    )
                else:
                    self.assertEqual(
                        "broad", metrics["query_pack_kind"]
                    )
                    self.assertEqual(1, metrics["member_count"])
                    self.assertEqual(
                        "broad-00", metrics["member_signal_ids"]
                    )
            self.assertEqual(quality["scan"]["skipped_large_files"], 0)
            self.assertEqual(quality["scan"]["pruned_large_assets"], 0)
            self.assertEqual(quality["scan"]["policy"], SCAN_POLICY)
            self.assertEqual(quality["scan"]["freshness"], SCAN_FRESHNESS)
            self.assertTrue(quality["scan"]["complete"])

    def test_discovery_query_tasks_resume_without_repeating_completed_call(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            sourcegraph = FakeDiscovery("sourcegraph")
            github = CrashOnceDiscovery("github-code-search")
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=sourcegraph,
                github_search=github,
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            budgets = self.budgets()
            with self.assertRaisesRegex(
                OSError, "synthetic discovery crash"
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=budgets,
                )
            with StateDB(root / ".state/collector.sqlite3") as state:
                failed = state.connection.execute(
                    """
                    SELECT run_id, base_release_id, status
                    FROM runs ORDER BY created_at DESC LIMIT 1
                    """
                ).fetchone()
                task_states = state.connection.execute(
                    """
                    SELECT status, COUNT(*) AS count
                    FROM tasks
                    WHERE run_id=? AND stage='discovery-query'
                    GROUP BY status
                    """,
                    (failed["run_id"],),
                ).fetchall()
                self.assertEqual("failed", failed["status"])
                self.assertEqual(
                    NO_LIVE_V2_RELEASE, failed["base_release_id"]
                )
                self.assertEqual(
                    {"complete": 1, "pending": 3},
                    {
                        row["status"]: row["count"]
                        for row in task_states
                    },
                )

            result = pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=budgets,
            )
            self.assertEqual(failed["run_id"], result["run_id"])
            self.assertEqual(2, sourcegraph.calls)
            self.assertEqual(3, github.calls)
            with StateDB(root / ".state/collector.sqlite3") as state:
                stage = state.connection.execute(
                    """
                    SELECT metrics_json FROM stages
                    WHERE run_id=? AND stage='discovery'
                    """,
                    (result["run_id"],),
                ).fetchone()
                metrics = json.loads(stage["metrics_json"])
                self.assertEqual(4, metrics["tasks_total"])
                self.assertEqual(4, metrics["tasks_completed"])
                self.assertEqual(1, metrics["tasks_reused"])
                self.assertEqual(0, metrics["queue_depth"])
                self.assertEqual(
                    1, metrics["sourcegraph_requests_this_invocation"]
                )
                self.assertEqual(
                    2, metrics["github_search_requests_this_invocation"]
                )
            self.assertEqual(
                1,
                result["report"]["discovery"][
                    "actual_sourcegraph_requests"
                ],
            )
            self.assertEqual(
                2,
                result["report"]["discovery"]["actual_github_requests"],
            )

    def test_metadata_batches_resume_without_repeating_completed_calls(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = root / "data"
            data.mkdir()
            (data / "current.json").write_text(json.dumps({
                "repos": [
                    {
                        "full_name": name,
                        "libraries": [{"library_id": "cublas"}],
                    }
                    for name in (
                        "public/legacy-a",
                        "public/legacy-b",
                    )
                ]
            }))
            metadata = CrashNearEndMetadata()
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=metadata,
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            budgets = self.budgets()
            with self.assertRaisesRegex(
                OSError, "synthetic metadata crash"
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=budgets,
                )
            self.assertEqual(
                [
                    "name:public/example",
                    "name:public/legacy-a",
                    "name:public/legacy-b",
                ],
                metadata.calls,
            )
            result = pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=budgets,
            )
            self.assertEqual(
                1, metadata.calls.count("name:public/example")
            )
            self.assertEqual(
                1, metadata.calls.count("name:public/legacy-a")
            )
            self.assertEqual(
                2, metadata.calls.count("name:public/legacy-b")
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                stage = state.connection.execute(
                    """
                    SELECT metrics_json FROM stages
                    WHERE run_id=? AND stage='metadata'
                    """,
                    (result["run_id"],),
                ).fetchone()
                metrics = json.loads(stage["metrics_json"])
                self.assertEqual(3, metrics["tasks_total"])
                self.assertEqual(3, metrics["tasks_completed"])
                self.assertEqual(2, metrics["tasks_reused"])
                self.assertEqual(0, metrics["queue_depth"])

    def test_preseeded_metadata_epoch_reuses_exact_docs_without_network(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = mock.Mock()
            metadata.resolve.side_effect = AssertionError(
                "preseeded initial metadata must not replay"
            )
            pipeline = CollectorPipeline(
                repo_root=root,
                metadata=metadata,
            )
            state_path = root / ".state/collector.sqlite3"
            observation = DiscoveryObservation(
                repo_full_name="public/example",
                repo_node_id="MDEwOlJlcG9zaXRvcnkx",
                library_id="cublas",
                signal_id="header-00",
                source="github-code-search",
                query_fingerprint="query",
                observed_at=NOW,
                visibility="PUBLIC",
            )
            payload = {
                "version": 1,
                "lookups": [{
                    "node_id": None,
                    "full_name": "public/example",
                }],
            }
            task_key = "batch:%06d:%s" % (
                0,
                fingerprint("github-metadata-task", payload)[:32],
            )
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
            state_known = (("R_current", "public/example"),)
            with StateDB(state_path) as state:
                state.create_run(
                    "successor", mode="reconcile", status="running"
                )
                task_id = state.enqueue_task(
                    "successor",
                    "github-metadata-batch",
                    task_key,
                    payload=payload,
                )
                leased = state.lease_task_by_id(
                    task_id, worker="fixture", lease_seconds=300
                )
                self.assertIsNotNone(leased)
                state.complete_task(
                    task_id, worker="fixture", result=document
                )
                row = state.connection.execute(
                    """
                    SELECT payload_json, result_json FROM tasks
                    WHERE task_id=?
                    """,
                    (task_id,),
                ).fetchone()
                task_universe = [{
                    "task_key": task_key,
                    "payload": json.loads(row["payload_json"]),
                }]
                result_universe = [{
                    "task_key": task_key,
                    "result_sha256": hashlib.sha256(
                        row["result_json"].encode()
                    ).hexdigest(),
                }]
                contract = {
                    "task_count": 1,
                    "lookup_count": 1,
                    "task_universe_sha256": hashlib.sha256(
                        canonical_json(task_universe).encode()
                    ).hexdigest(),
                    "result_universe_sha256": hashlib.sha256(
                        canonical_json(result_universe).encode()
                    ).hexdigest(),
                    "input_context_sha256": (
                        _metadata_input_context_sha256(
                            (observation,), {}, state_known
                        )
                    ),
                }
                (
                    resolution,
                    publishable,
                    by_name,
                    by_node,
                ) = pipeline._resolve_metadata(
                    state,
                    (observation,),
                    {},
                    state_known,
                    run_id="successor",
                    budgets=RunBudgets.reconcile(),
                    reuse_completed_epoch=True,
                    preseeded_epoch_contract=contract,
                )
            metadata.resolve.assert_not_called()
            self.assertEqual(1, resolution.request_count)
            self.assertIn("public/example", publishable)
            self.assertEqual(
                "R_current",
                by_name["public/example"].node_id,
            )
            self.assertEqual(
                "R_current", by_node["R_current"].node_id
            )

    def test_metadata_resume_reuses_only_newest_complete_fresh_epoch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = mock.Mock()
            metadata.resolve.side_effect = AssertionError(
                "completed fresh metadata must not replay"
            )
            pipeline = CollectorPipeline(repo_root=root, metadata=metadata)
            state_path = root / ".state/collector.sqlite3"

            def add_result(state, task_key, node_id, full_name):
                payload = {
                    "version": 1,
                    "lookups": [{"node_id": node_id, "full_name": full_name}],
                }
                repository = RepositoryMetadata(
                    request_key="node:" + node_id,
                    requested_node_id=node_id,
                    requested_full_name=full_name,
                    node_id=node_id,
                    full_name=full_name,
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
                        reset_at="2026-08-02T00:00:00Z",
                    )
                )
                task_id = state.enqueue_task(
                    "successor",
                    "github-metadata-batch",
                    task_key,
                    payload=payload,
                )
                leased = state.lease_task_by_id(
                    task_id, worker="fixture", lease_seconds=300
                )
                self.assertIsNotNone(leased)
                state.complete_task(
                    task_id, worker="fixture", result=document
                )

            with StateDB(state_path) as state:
                state.create_run(
                    "successor", mode="reconcile", status="running"
                )
                add_result(
                    state,
                    "batch:000000:preseeded",
                    "R_preseeded",
                    "public/preseeded",
                )
                add_result(
                    state,
                    "fresh:%s:batch:000000:old" % ("1" * 16),
                    "R_old_fresh",
                    "public/old-fresh",
                )
                add_result(
                    state,
                    "fresh:%s:batch:000000:new" % ("2" * 16),
                    "R_new_fresh",
                    "public/new-fresh",
                )
                resolution, publishable, by_name, by_node = (
                    pipeline._resolve_metadata(
                        state,
                        (),
                        {},
                        (("R_new_fresh", "public/new-fresh"),),
                        run_id="successor",
                        budgets=RunBudgets.reconcile(),
                        reuse_completed_epoch=True,
                    )
                )
            metadata.resolve.assert_not_called()
            self.assertEqual(
                ["R_new_fresh"],
                [repository.node_id for repository in resolution.repositories],
            )
            self.assertEqual({"public/new-fresh"}, set(publishable))
            self.assertEqual("R_new_fresh", by_name["public/new-fresh"].node_id)
            self.assertEqual("R_new_fresh", by_node["R_new_fresh"].node_id)

    def test_metadata_resume_continues_exact_partial_fresh_epoch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            calls = []

            def resolve(lookups, **_kwargs):
                lookups = list(lookups)
                calls.extend(lookup.key for lookup in lookups)
                repositories = tuple(RepositoryMetadata(
                    request_key=lookup.key,
                    requested_node_id=lookup.node_id,
                    requested_full_name=lookup.full_name,
                    node_id=lookup.node_id,
                    full_name=lookup.full_name,
                    visibility="PUBLIC",
                    is_private=False,
                    is_fork=False,
                    is_archived=False,
                    default_branch="main",
                    head_oid="a" * 40,
                    renamed=False,
                    status="ok",
                ) for lookup in lookups)
                return GraphQLResolution(
                    repositories, (), 1, 1, 4999,
                    "2026-08-03T00:00:00Z",
                )

            metadata = mock.Mock()
            metadata.resolve.side_effect = resolve
            pipeline = CollectorPipeline(repo_root=root, metadata=metadata)
            state_path = root / ".state/collector.sqlite3"
            epoch = "3" * 16
            known = (
                ("R_a", "public/a"),
                ("R_b", "public/b"),
            )
            with StateDB(state_path) as state:
                state.create_run(
                    "successor", mode="reconcile", status="running"
                )
                keys = []
                for ordinal, (node_id, full_name) in enumerate(known):
                    payload = {
                        "version": 1,
                        "lookups": [{
                            "node_id": node_id,
                            "full_name": full_name,
                        }],
                    }
                    key = "fresh:%s:batch:%06d:%s" % (
                        epoch,
                        ordinal,
                        fingerprint(
                            "github-metadata-task", payload
                        )[:32],
                    )
                    keys.append((key, payload))
                first_id = state.enqueue_task(
                    "successor",
                    "github-metadata-batch",
                    keys[0][0],
                    payload=keys[0][1],
                )
                first_lookup = RepositoryMetadata(
                    request_key="node:R_a",
                    requested_node_id="R_a",
                    requested_full_name="public/a",
                    node_id="R_a",
                    full_name="public/a",
                    visibility="PUBLIC",
                    is_private=False,
                    is_fork=False,
                    is_archived=False,
                    default_branch="main",
                    head_oid="a" * 40,
                    renamed=False,
                    status="ok",
                )
                leased = state.lease_task_by_id(
                    first_id, worker="fixture", lease_seconds=300
                )
                self.assertIsNotNone(leased)
                state.complete_task(
                    first_id,
                    worker="fixture",
                    result=_metadata_result_to_task_result(
                        GraphQLResolution(
                            (first_lookup,), (), 1, 1, 4999,
                            "2026-08-03T00:00:00Z",
                        )
                    ),
                )
                state.enqueue_task(
                    "successor",
                    "github-metadata-batch",
                    keys[1][0],
                    payload=keys[1][1],
                )
                with mock.patch.object(
                    pipeline, "_metadata_batch_size", return_value=1
                ):
                    resolution, publishable, _by_name, _by_node = (
                        pipeline._resolve_metadata(
                            state,
                            (),
                            {},
                            known,
                            run_id="successor",
                            budgets=RunBudgets.reconcile(),
                            force_refresh=True,
                            resume_incomplete_fresh_epoch=True,
                        )
                    )
            self.assertEqual(["node:R_b"], calls)
            self.assertEqual(2, len(resolution.repositories))
            self.assertEqual({"public/a", "public/b"}, set(publishable))

    def test_metadata_recovery_selects_reviewed_older_fresh_epoch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            calls = []

            def resolve(lookups, **_kwargs):
                lookups = list(lookups)
                calls.extend(lookup.key for lookup in lookups)
                repositories = tuple(RepositoryMetadata(
                    request_key=lookup.key,
                    requested_node_id=lookup.node_id,
                    requested_full_name=lookup.full_name,
                    node_id=lookup.node_id,
                    full_name=lookup.full_name,
                    visibility="PUBLIC",
                    is_private=False,
                    is_fork=False,
                    is_archived=False,
                    default_branch="main",
                    head_oid="a" * 40,
                    renamed=False,
                    status="ok",
                ) for lookup in lookups)
                return GraphQLResolution(
                    repositories, (), 1, 1, 4999,
                    "2026-08-03T00:00:00Z",
                )

            metadata = mock.Mock()
            metadata.resolve.side_effect = resolve
            pipeline = CollectorPipeline(repo_root=root, metadata=metadata)
            state_path = root / ".state/collector.sqlite3"
            reviewed_epoch = "4" * 16
            replacement_epoch = "5" * 16
            known = (("R_a", "public/a"),)
            payload = {
                "version": 1,
                "lookups": [{
                    "node_id": "R_a", "full_name": "public/a",
                }],
            }
            suffix = "batch:000000:%s" % (
                fingerprint("github-metadata-task", payload)[:32],
            )
            with StateDB(state_path) as state:
                state.create_run(
                    "successor", mode="reconcile", status="running"
                )
                state.enqueue_task(
                    "successor",
                    "github-metadata-batch",
                    "fresh:%s:%s" % (reviewed_epoch, suffix),
                    payload=payload,
                )
                state.enqueue_task(
                    "successor",
                    "github-metadata-batch",
                    "fresh:%s:%s" % (replacement_epoch, suffix),
                    payload=payload,
                )
                with mock.patch.object(
                    pipeline, "_metadata_batch_size", return_value=1
                ):
                    resolution, publishable, _by_name, _by_node = (
                        pipeline._resolve_metadata(
                            state,
                            (),
                            {},
                            known,
                            run_id="successor",
                            budgets=RunBudgets.reconcile(),
                            force_refresh=True,
                            resume_incomplete_fresh_epoch=True,
                            resume_fresh_metadata_epoch=reviewed_epoch,
                        )
                    )
            self.assertEqual(["node:R_a"], calls)
            self.assertEqual(1, len(resolution.repositories))
            self.assertEqual({"public/a"}, set(publishable))

    def test_metadata_recovery_validates_before_enqueuing_changed_plan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root, metadata=mock.Mock()
            )
            state_path = root / ".state/collector.sqlite3"
            epoch = "6" * 16
            payload = {
                "version": 1,
                "lookups": [{
                    "node_id": "R_a", "full_name": "public/a",
                }],
            }
            key = "fresh:%s:batch:000000:%s" % (
                epoch,
                fingerprint("github-metadata-task", payload)[:32],
            )
            with StateDB(state_path) as state:
                state.create_run(
                    "successor", mode="reconcile", status="running"
                )
                state.enqueue_task(
                    "successor", "github-metadata-batch", key,
                    payload=payload,
                )
                with (
                    mock.patch.object(
                        pipeline, "_metadata_batch_size", return_value=1
                    ),
                    self.assertRaisesRegex(
                        PipelineError,
                        "reviewed partial fresh metadata epoch changed",
                    ),
                ):
                    pipeline._resolve_metadata(
                        state,
                        (),
                        {},
                        (("R_b", "public/b"),),
                        run_id="successor",
                        budgets=RunBudgets.reconcile(),
                        force_refresh=True,
                        resume_incomplete_fresh_epoch=True,
                        resume_fresh_metadata_epoch=epoch,
                    )
                task_count = state.connection.execute(
                    "SELECT COUNT(*) FROM tasks WHERE run_id='successor'"
                ).fetchone()[0]
            self.assertEqual(1, task_count)

    def test_post_refresh_metadata_reuses_certified_complete_epoch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = mock.Mock()
            pipeline = CollectorPipeline(repo_root=root, metadata=metadata)
            state_path = root / ".state/collector.sqlite3"
            epoch = "7" * 16
            missing_node = "R_missing"
            missing_name = "public/missing"
            public_node = "R_public"
            public_name = "public/promoted"
            fixtures = (
                (
                    {"node_id": missing_node, "full_name": missing_name},
                    RepositoryMetadata(
                        request_key="node:" + missing_node,
                        requested_node_id=missing_node,
                        requested_full_name=missing_name,
                        node_id=None,
                        full_name=None,
                        visibility=None,
                        is_private=None,
                        is_fork=None,
                        is_archived=None,
                        default_branch=None,
                        head_oid=None,
                        renamed=False,
                        status="missing",
                    ),
                ),
                (
                    {"node_id": None, "full_name": public_name},
                    RepositoryMetadata(
                        request_key="name:" + public_name,
                        requested_node_id=None,
                        requested_full_name=public_name,
                        node_id=public_node,
                        full_name=public_name,
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
            )
            missing_proof = None
            with StateDB(state_path) as state:
                state.create_run(
                    "successor", mode="reconcile", status="running"
                )
                for ordinal, (lookup, repository) in enumerate(fixtures):
                    payload = {"version": 1, "lookups": [lookup]}
                    key = "fresh:%s:batch:%06d:%s" % (
                        epoch,
                        ordinal,
                        fingerprint(
                            "github-metadata-task", payload
                        )[:32],
                    )
                    task_id = state.enqueue_task(
                        "successor", "github-metadata-batch", key,
                        payload=payload,
                    )
                    leased = state.lease_task_by_id(
                        task_id, worker="fixture", lease_seconds=300
                    )
                    self.assertIsNotNone(leased)
                    document = _metadata_result_to_task_result(
                        GraphQLResolution(
                            (repository,), (), 1, 1, 4999, None
                        )
                    )
                    state.complete_task(
                        task_id, worker="fixture", result=document
                    )
                    if repository.status == "missing":
                        missing_proof = [{
                            "task_id": task_id,
                            "task_key_sha256": hashlib.sha256(
                                key.encode("utf-8")
                            ).hexdigest(),
                            "repository": document["repositories"][0],
                        }]
                self.assertIsNotNone(missing_proof)
                sha256 = lambda value: hashlib.sha256(
                    canonical_json(value).encode("utf-8")
                ).hexdigest()
                control = {
                    "fresh_metadata_epoch": epoch,
                    "fresh_metadata_batch_count": 2,
                    "fresh_missing_metadata_proof_sha256": sha256(
                        missing_proof
                    ),
                    "additional_purged_repository_nodes_sha256": sha256(
                        [missing_node]
                    ),
                }
                with mock.patch.object(
                    pipeline, "_metadata_batch_size", return_value=1
                ):
                    resolution, publishable, _by_name, _by_node = (
                        pipeline._resolve_metadata(
                            state,
                            (),
                            {missing_name: {"cublas"}},
                            ((public_node, public_name),),
                            run_id="successor",
                            budgets=RunBudgets.reconcile(),
                            force_refresh=True,
                            resume_incomplete_fresh_epoch=True,
                            resume_fresh_metadata_epoch=epoch,
                            post_refresh_privacy_control=control,
                        )
                    )
                task_count = state.connection.execute(
                    "SELECT COUNT(*) FROM tasks WHERE run_id='successor'"
                ).fetchone()[0]
            metadata.resolve.assert_not_called()
            self.assertEqual(2, len(resolution.repositories))
            self.assertEqual({public_name}, set(publishable))
            self.assertEqual(2, task_count)

    def test_graphql_budget_deduplicates_certified_embedded_epoch(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "collector.sqlite3"
            document = _metadata_result_to_task_result(
                GraphQLResolution((), (), 1, 1, 4999, None)
            )
            with StateDB(state_path) as state:
                task_result_json = canonical_json(document)
                result_universe = [{
                    "task_key": "batch:000000:embedded",
                    "result_sha256": hashlib.sha256(
                        task_result_json.encode()
                    ).hexdigest(),
                }]
                state.create_run(
                    "successor",
                    mode="reconcile",
                    status="running",
                    plan={"execution_contract": {
                        "historical_graphql_usage": {
                            "request_count": 1,
                            "points_used": 1,
                            "remaining": None,
                            "reset_at": None,
                        },
                        "graphql_resume_control": {
                            "embedded_task_count": 1,
                            "embedded_request_count": 1,
                            "embedded_points_used": 1,
                            "embedded_result_universe_sha256": hashlib.sha256(
                                canonical_json(result_universe).encode()
                            ).hexdigest(),
                        },
                    }},
                )
                for key in (
                    "batch:000000:embedded",
                    "fresh:epoch00000000000:batch:000000:fresh",
                ):
                    task_id = state.enqueue_task(
                        "successor",
                        "github-metadata-batch",
                        key,
                        payload={"version": 1, "lookups": []},
                    )
                    leased = state.lease_task_by_id(
                        task_id, worker="fixture", lease_seconds=300
                    )
                    self.assertIsNotNone(leased)
                    state.complete_task(
                        task_id, worker="fixture", result=document
                    )
                budget = _graphql_journal_budget(state, "successor")
            self.assertEqual(2, budget["request_count"])
            self.assertEqual(2, budget["points_used"])

    def test_privacy_resume_pins_surviving_metadata_to_scanned_head(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "collector.sqlite3"
            old_head = "a" * 40
            fresh_head = "b" * 40
            repository = RepositoryMetadata(
                request_key="node:R_public",
                requested_node_id="R_public",
                requested_full_name=None,
                node_id="R_public",
                full_name="public/example",
                visibility="PUBLIC",
                is_private=False,
                is_fork=False,
                is_archived=False,
                default_branch="main",
                head_oid=fresh_head,
                renamed=False,
                status="ok",
            )
            with StateDB(state_path) as state:
                state.create_run(
                    "successor", mode="reconcile", status="running"
                )
                state.upsert_repository({
                    "node_id": "R_public",
                    "full_name": "public/example",
                    "visibility": "public",
                    "head_sha": fresh_head,
                })
                state.enqueue_task(
                    "successor",
                    "scan",
                    "c" * 64,
                    repository_id="R_public",
                    payload={
                        "full_name": "public/example",
                        "head_sha": old_head,
                        "libraries": ["cublas"],
                    },
                )
                with mock.patch(
                    "collector.pipeline._validate_phase8_privacy_resume_control",
                    return_value={
                        "current_scan_task_count": 1,
                        "scan_head_pin_count": 1,
                        "scan_bound_rename_count": 0,
                    },
                ):
                    pinned = _pin_phase8_scan_bound_metadata(
                        state,
                        "successor",
                        {"public/example": repository},
                        {
                            "privacy_resume_control": {},
                            "graphql_resume_control": {},
                        },
                    )
                durable_head = state.connection.execute(
                    "SELECT head_sha FROM repositories WHERE node_id='R_public'"
                ).fetchone()[0]
            self.assertEqual(old_head, pinned["public/example"].head_oid)
            self.assertEqual(old_head, durable_head)

    def test_privacy_resume_pins_deferred_proof_to_control_bound_head(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_path = root / "collector.sqlite3"
            old_head = "a" * 40
            fresh_head = "b" * 40
            library = next(
                item for item in LIBRARIES if item["id"] == "cublas"
            )
            plan = build_plan(
                mode="onboard",
                state_path=state_path,
                data_dir=root / "data",
                libraries=[library],
            )
            values = plan.fingerprints.libraries["cublas"]
            repository = RepositoryMetadata(
                request_key="node:R_deferred",
                requested_node_id="R_deferred",
                requested_full_name="public/deferred",
                node_id="R_deferred",
                full_name="public/deferred",
                visibility="PUBLIC",
                is_private=False,
                is_fork=False,
                is_archived=False,
                default_branch="main",
                head_oid=fresh_head,
                renamed=False,
                status="ok",
            )
            task_key = fingerprint(
                "scan-task-v2",
                {
                    "repository_node_id": repository.node_id,
                    "head_sha": old_head,
                    "candidate_library_ids": ["cublas"],
                    "analysis_only": False,
                    "ai_fingerprint": None,
                    "detector_fingerprints": {
                        "cublas": _library_fp_values(
                            plan, "cublas"
                        )["detector"]
                    },
                },
            )
            identity_sha256 = hashlib.sha256(
                b"R_deferred\0public/deferred"
            ).hexdigest()
            head_pin = {
                "task_key": task_key,
                "repository_identity_sha256": identity_sha256,
                "head_sha": old_head,
                "libraries": ["cublas"],
            }
            post_control = {
                "current_scan_task_count": 0,
                "scan_head_pin_count": 0,
                "scan_bound_rename_count": 0,
                "deferred_scan_head_pins": [head_pin],
            }
            with StateDB(state_path) as state:
                mutable_values = values.as_dict()
                mutable_values["detector"] = "f" * 64
                state.upsert_library(
                    "cublas",
                    catalog={"name": "cuBLAS"},
                    fingerprints={
                        **mutable_values,
                        "dating": plan.fingerprints.dating,
                        "aggregation": plan.fingerprints.aggregation,
                    },
                )
                state.upsert_repository({
                    "node_id": repository.node_id,
                    "full_name": repository.full_name,
                    "visibility": "public",
                    "head_sha": fresh_head,
                })
                state.create_run(
                    "successor",
                    mode="reconcile",
                    fingerprints=plan.fingerprints.as_dict(),
                    status="running",
                )
                with mock.patch(
                    "collector.pipeline._validate_phase8_privacy_resume_control",
                    return_value={
                        "current_scan_task_count": 0,
                        "scan_head_pin_count": 0,
                        "scan_bound_rename_count": 0,
                    },
                ), mock.patch(
                    "collector.pipeline._validate_phase8_post_refresh_privacy_control",
                    return_value=post_control,
                ):
                    pinned = _pin_phase8_scan_bound_metadata(
                        state,
                        "successor",
                        {repository.full_name: repository},
                        {
                            "privacy_resume_control": {},
                            "graphql_resume_control": {},
                            "visibility_epoch_recovery_control": {},
                            "post_refresh_privacy_control": {},
                            "fresh_candidate_deferral_control": {
                                "deferred_task_proof": [{
                                    "task_key": task_key,
                                    "repository_identity_sha256": (
                                        identity_sha256
                                    ),
                                    "libraries": ["cublas"],
                                }],
                            },
                        },
                    )
                durable_head = state.connection.execute(
                    """
                    SELECT head_sha FROM repositories
                    WHERE node_id='R_deferred'
                    """
                ).fetchone()[0]
            self.assertEqual(old_head, pinned[repository.full_name].head_oid)
            self.assertEqual(old_head, durable_head)

    def test_post_refresh_privacy_supersedes_effective_scan_partition(self):
        privacy = {"contract_sha256": "a" * 64}
        post_refresh = {
            "current_scan_task_count": 38286,
            "current_completed_scan_task_count": 37968,
            "current_deferred_scan_task_count": 318,
            "scan_head_pin_count": 1538,
            "scan_bound_rename_count": 16,
        }
        contract = {
            "privacy_resume_control": {},
            "graphql_resume_control": {},
            "visibility_epoch_recovery_control": {},
            "post_refresh_privacy_control": {},
        }
        with (
            mock.patch(
                "collector.pipeline._validate_phase8_privacy_resume_control",
                return_value=privacy,
            ),
            mock.patch(
                "collector.pipeline._validate_phase8_post_refresh_privacy_control",
                return_value=post_refresh,
            ) as validate_post,
        ):
            effective = _phase8_effective_privacy_control(contract)
        self.assertEqual(post_refresh, effective)
        validate_post.assert_called_once_with(
            {}, privacy, contract["visibility_epoch_recovery_control"]
        )

    def test_preseeded_metadata_execution_contract_validates_hashes(self):
        contract = self.cohort_contract(
            "cublas", metadata_batch_size=50
        )
        contract["preseeded_metadata_epoch"] = {
            "task_count": 774,
            "lookup_count": 38_698,
            "task_universe_sha256": "a" * 64,
            "result_universe_sha256": "b" * 64,
            "input_context_sha256": "c" * 64,
        }
        validated = _validate_reviewed_execution_contract(
            contract,
            mode="reconcile",
            wanted={"cublas"},
            budgets=RunBudgets.reconcile(),
            metadata_batch_size=50,
        )
        self.assertEqual(
            contract["preseeded_metadata_epoch"],
            validated["preseeded_metadata_epoch"],
        )
        invalid = copy.deepcopy(contract)
        invalid["preseeded_metadata_epoch"][
            "result_universe_sha256"
        ] = "not-a-sha256"
        with self.assertRaisesRegex(
            PipelineError, "preseeded metadata contract"
        ):
            _validate_reviewed_execution_contract(
                invalid,
                mode="reconcile",
                wanted={"cublas"},
                budgets=RunBudgets.reconcile(),
                metadata_batch_size=50,
            )

    def test_reviewed_cohort_wall_extension_changes_only_wall_budget(self):
        baseline = RunBudgets.reconcile()
        extended = dataclasses.replace(
            baseline, max_wall_seconds=96 * 3600
        )
        contract = self.cohort_contract("cublas")
        unchanged = extended.to_dict()
        unchanged.pop("max_wall_seconds")
        contract.update({
            "wall_extension": {
                "version": 1,
                "original_limit_seconds": baseline.max_wall_seconds,
                "extended_limit_seconds": extended.max_wall_seconds,
                "reason": "phase8_owner_wall_extension",
                "authorized_at": "2026-07-31T15:00:00.000000Z",
                "predecessor_source_commit": "a" * 40,
                "successor_source_commit": "b" * 40,
                "source_audit_sha256": "c" * 64,
                "unchanged_budgets_sha256": hashlib.sha256(
                    canonical_json(unchanged).encode("utf-8")
                ).hexdigest(),
                "prior_historical_wall_seconds": 0.0,
                "pre_extension_run_elapsed_seconds": 1.0,
                "charged_wall_seconds": 1.0,
            },
            "historical_wall_seconds": 1.0,
            "reviewed_slo": {
                "class": "partial_cohort_reconciliation",
                "target_seconds": 24 * 3600,
                "ceiling_seconds": extended.max_wall_seconds,
            },
        })
        validated = _validate_reviewed_execution_contract(
            contract,
            mode="reconcile",
            wanted={"cublas"},
            budgets=extended,
            metadata_batch_size=1,
        )
        self.assertEqual(contract, validated)

        changed_fetches = dataclasses.replace(
            extended, max_fetches=extended.max_fetches + 1
        )
        with self.assertRaisesRegex(
            PipelineError, "changed another budget"
        ):
            _validate_reviewed_execution_contract(
                contract,
                mode="reconcile",
                wanted={"cublas"},
                budgets=changed_fetches,
                metadata_batch_size=1,
            )

        invalid_proof = copy.deepcopy(contract)
        invalid_proof["wall_extension"][
            "unchanged_budgets_sha256"
        ] = "d" * 64
        with self.assertRaisesRegex(PipelineError, "budget proof"):
            _validate_reviewed_execution_contract(
                invalid_proof,
                mode="reconcile",
                wanted={"cublas"},
                budgets=extended,
                metadata_batch_size=1,
            )

        shared = current_fingerprints().filters["shared"]
        filter_proof = {
            "version": 1,
            "kind": (
                "phase8-exact-buildozer-generated-output-filter-extension"
            ),
            "directory_segment": ".buildozer",
            "policy": "monotonic-exclusion-certified-result-migration",
            "prior_shared_filter_sha256": "d" * 64,
            "current_shared_filter_sha256": shared,
            "source_proof_sha256": "e" * 64,
            "completed_scan_tasks_certified": 17,
            "completed_result_documents_sha256": "f" * 64,
            "completed_results_with_buildozer_evidence": 0,
            "certified_checkpoint_scan_result_count": 0,
            "certified_checkpoint_repository_count": 0,
            "certified_checkpoint_certificate_sha256": "7" * 64,
            "migrated_scan_result_count": 41,
            "migrated_repository_count": 17,
            "migrated_scan_results_sha256": "4" * 64,
            "migrated_scan_task_key_count": 17,
            "migrated_scan_task_keys_sha256": "5" * 64,
            "target_detector_fingerprints_sha256": "6" * 64,
            "incident_task_id": 42,
            "incident_prior_task_key": "prior-shoot-task",
            "incident_task_key": "shoot-task",
            "incident_repository_id": "R_shoot",
            "incident_full_name": "Silian1234/shootAnalyzer",
            "incident_head_sha": "1" * 40,
            "incident_prior_attempts": 1,
            "tracked_buildozer_path_count": 11,
            "tracked_buildozer_paths_sha256": "2" * 64,
            "case_collision_count": 1,
            "case_collisions_sha256": "3" * 64,
        }
        filter_proof["contract_sha256"] = hashlib.sha256(
            canonical_json(filter_proof).encode("utf-8")
        ).hexdigest()
        contract["filter_extension"] = filter_proof
        validated = _validate_reviewed_execution_contract(
            contract,
            mode="reconcile",
            wanted={"cublas"},
            budgets=extended,
            metadata_batch_size=1,
        )
        self.assertEqual(filter_proof, validated["filter_extension"])

        invalid_filter = copy.deepcopy(contract)
        invalid_filter["filter_extension"][
            "completed_results_with_buildozer_evidence"
        ] = 1
        with self.assertRaisesRegex(PipelineError, "filter extension"):
            _validate_reviewed_execution_contract(
                invalid_filter,
                mode="reconcile",
                wanted={"cublas"},
                budgets=extended,
                metadata_batch_size=1,
            )

        chained = copy.deepcopy(contract)
        chained["filter_extension"]["current_shared_filter_sha256"] = (
            "8" * 64
        )
        chained_filter_document = dict(chained["filter_extension"])
        chained_filter_document.pop("contract_sha256")
        chained["filter_extension"]["contract_sha256"] = hashlib.sha256(
            canonical_json(chained_filter_document).encode("utf-8")
        ).hexdigest()
        current_document = current_fingerprints().as_dict()
        scanner_migration = {
            "version": 1,
            "kind": (
                "phase8-audited-scanner-source-compatibility-migration"
            ),
            "policy": "exact-source-monotonic-result-preservation",
            "predecessor_source_commit": (
                "aafdc5e14d6b814b5e53e59f266c485bdffc586b"
            ),
            "audited_issue_commit": (
                "b1e69e56ef030623848dbac351d06d0bd833209f"
            ),
            "successor_source_commit": "3" * 40,
            "changed_issue_paths": [
                "collector/config.py",
                "collector/repo_cache.py",
                "collector/scan.py",
                "test_req14_content_materialization.py",
                "test_req14_scanner.py",
            ],
            "changed_control_paths": ["collector/pipeline.py"],
            "source_audit_sha256": "4" * 64,
            "prior_fingerprints_sha256": "5" * 64,
            "current_fingerprints_sha256": hashlib.sha256(
                canonical_json(current_document).encode("utf-8")
            ).hexdigest(),
            "prior_shared_filter_sha256": "8" * 64,
            "current_shared_filter_sha256": current_document["filters"][
                "shared"
            ],
            "prior_network_task_source_sha256": "6" * 64,
            "current_network_task_source_sha256": (
                _network_task_source_sha256()
            ),
            "task_universe_count": 38321,
            "completed_scan_tasks_certified": 37931,
            "completed_result_documents_sha256": "7" * 64,
            "completed_results_with_virtual_documents_evidence": 0,
            "certified_checkpoint_scan_result_count": 37,
            "certified_checkpoint_repository_count": 37,
            "certified_checkpoint_certificate_sha256": "9" * 64,
            "migrated_scan_result_count": 87000,
            "migrated_repository_count": 37931,
            "migrated_scan_results_sha256": "a" * 64,
            "migrated_scan_task_key_count": 38321,
            "migrated_scan_task_keys_sha256": "b" * 64,
            "target_detector_fingerprints_sha256": "c" * 64,
        }
        scanner_migration["contract_sha256"] = hashlib.sha256(
            canonical_json(scanner_migration).encode("utf-8")
        ).hexdigest()
        chained["scanner_source_migration"] = scanner_migration
        chained["network_task_source_sha256"] = (
            _network_task_source_sha256()
        )
        validated = _validate_reviewed_execution_contract(
            chained,
            mode="reconcile",
            wanted={"cublas"},
            budgets=extended,
            metadata_batch_size=1,
        )
        self.assertEqual(
            scanner_migration, validated["scanner_source_migration"]
        )

        invalid_migration = copy.deepcopy(chained)
        invalid_migration["scanner_source_migration"][
            "completed_results_with_virtual_documents_evidence"
        ] = 1
        with self.assertRaisesRegex(PipelineError, "scanner source migration"):
            _validate_reviewed_execution_contract(
                invalid_migration,
                mode="reconcile",
                wanted={"cublas"},
                budgets=extended,
                metadata_batch_size=1,
            )

        resumed = copy.deepcopy(chained)
        resumed_migration = resumed["scanner_source_migration"]
        resumed_migration["current_network_task_source_sha256"] = "d" * 64
        resumed_migration_document = dict(resumed_migration)
        resumed_migration_document.pop("contract_sha256")
        resumed_migration["contract_sha256"] = hashlib.sha256(
            canonical_json(resumed_migration_document).encode("utf-8")
        ).hexdigest()
        current_fingerprint_sha256 = hashlib.sha256(
            canonical_json(current_document).encode("utf-8")
        ).hexdigest()
        resume_control = {
            "version": 1,
            "kind": "phase8-audited-scanner-resume-control",
            "policy": "source-only-durable-status-partition",
            "predecessor_source_commit": (
                "3c40267b9844a84aa6d08c2f6a897c81a950fcb4"
            ),
            "successor_source_commit": "e" * 40,
            "required_control_commits": [
                "3ffc6eb48d33040ea6e218499a89444f75050997",
                "6b9528d7f6c5f2506ecee15f18bde56a81886bff",
            ],
            "changed_paths": sorted({
                ".gitlab-ci.yml",
                "collector/cli.py",
                "collector/phase8_resume_control.py",
                "collector/pipeline.py",
                "collector/state.py",
                "docs/Documentation.md",
                "docs/PROJECT-CONTEXT.md",
                "test_req14_pipeline.py",
                "test_req14_resume_control.py",
                "test_req14_scan_attempts.py",
            }),
            "source_audit_sha256": "1" * 64,
            "prior_fingerprints_sha256": current_fingerprint_sha256,
            "current_fingerprints_sha256": current_fingerprint_sha256,
            "prior_network_task_source_sha256": "d" * 64,
            "current_network_task_source_sha256": (
                _network_task_source_sha256()
            ),
            "scanner_migration_contract_sha256": resumed_migration[
                "contract_sha256"
            ],
            "task_universe_count": 38321,
            "completed_scan_task_count": 37931,
            "failed_scan_task_count": 195,
            "pending_scan_task_count": 195,
            "running_scan_task_count": 0,
            "scan_attempt_count": 38489,
            "scan_result_count": 212267,
            "preserved_state_sha256": "2" * 64,
        }
        resume_control["contract_sha256"] = hashlib.sha256(
            canonical_json(resume_control).encode("utf-8")
        ).hexdigest()
        resumed["scanner_resume_control"] = resume_control
        resumed["network_task_source_sha256"] = (
            _network_task_source_sha256()
        )
        validated = _validate_reviewed_execution_contract(
            resumed,
            mode="reconcile",
            wanted={"cublas"},
            budgets=extended,
            metadata_batch_size=1,
        )
        self.assertEqual(
            resume_control, validated["scanner_resume_control"]
        )

        invalid_resume = copy.deepcopy(resumed)
        invalid_resume["scanner_resume_control"][
            "pending_scan_task_count"
        ] += 1
        invalid_resume_document = dict(
            invalid_resume["scanner_resume_control"]
        )
        invalid_resume_document.pop("contract_sha256")
        invalid_resume["scanner_resume_control"][
            "contract_sha256"
        ] = hashlib.sha256(
            canonical_json(invalid_resume_document).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(PipelineError, "scanner resume control"):
            _validate_reviewed_execution_contract(
                invalid_resume,
                mode="reconcile",
                wanted={"cublas"},
                budgets=extended,
                metadata_batch_size=1,
            )

    def test_final_visibility_flip_private_aborts_then_resume_refreshes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = MutableVisibilityMetadata()

            def flip_private_after_scan(*args, **kwargs):
                outcomes = fake_scan_runner(*args, **kwargs)
                metadata.private = True
                return outcomes

            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=metadata,
                scan_runner=flip_private_after_scan,
                citation_pipeline=FakeCitationPipeline(),
            )
            with self.assertRaisesRegex(
                PipelineError, "private, gone, forked, archived"
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=self.budgets(),
                )
            self.assertFalse((root / "data/v2/manifest.json").exists())
            self.assertEqual(1, metadata.initial_calls)
            self.assertEqual(1, metadata.final_calls)
            with StateDB(root / ".state/collector.sqlite3") as state:
                run_id = state.connection.execute(
                    "SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1"
                ).fetchone()["run_id"]
                stage = state.connection.execute(
                    """
                    SELECT status FROM stages
                    WHERE run_id=? AND stage='final_visibility'
                    """,
                    (run_id,),
                ).fetchone()
                self.assertEqual("failed", stage["status"])
                task = state.connection.execute(
                    """
                    SELECT status, result_json FROM tasks
                    WHERE run_id=?
                      AND stage='github-final-visibility-batch'
                    """,
                    (run_id,),
                ).fetchone()
                document = json.loads(task["result_json"])
                self.assertEqual("complete", task["status"])
                self.assertEqual(1, document["points_used"])
                self.assertIsNone(
                    document["repositories"][0].get("full_name")
                )

            metadata.private = False
            pipeline.scan_runner = fake_scan_runner
            result = pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self.budgets(),
            )
            self.assertEqual(run_id, result["run_id"])
            self.assertEqual(2, metadata.initial_calls)
            self.assertEqual(2, metadata.final_calls)
            self.assertTrue((root / "data/v2/manifest.json").exists())

    def test_final_visibility_accepts_only_certified_missing_node(self):
        node_id = "R_certified_missing"
        result = GraphQLResolution(
            repositories=(RepositoryMetadata(
                request_key="node:" + node_id,
                requested_node_id=node_id,
                requested_full_name=None,
                # Journal reconstruction preserves the requested stable ID
                # in ``node_id`` even though the sealed raw missing response
                # contains no canonical node.
                node_id=node_id,
                full_name=None,
                visibility=None,
                is_private=None,
                is_fork=None,
                is_archived=None,
                default_branch=None,
                head_oid=None,
                renamed=False,
                status="missing",
            ),),
            errors=(),
            request_count=1,
            points_used=1,
            remaining=4999,
            reset_at="2026-08-02T18:00:00Z",
        )
        _assert_final_visibility_part(
            result, (node_id,),
            certified_missing_node_ids=(node_id,),
        )
        with self.assertRaisesRegex(
            PipelineError, "private, gone, forked, archived"
        ):
            _assert_final_visibility_part(result, (node_id,))

    def test_final_visibility_partial_failure_preserves_last_good(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = MutableVisibilityMetadata()

            def become_partial_after_scan(*args, **kwargs):
                outcomes = fake_scan_runner(*args, **kwargs)
                metadata.partial = True
                return outcomes

            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=metadata,
                scan_runner=become_partial_after_scan,
                citation_pipeline=FakeCitationPipeline(),
            )
            with self.assertRaisesRegex(
                PipelineError, "partial errors"
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=self.budgets(),
                )
            self.assertFalse((root / "data/v2/manifest.json").exists())
            with StateDB(root / ".state/collector.sqlite3") as state:
                document = json.loads(state.connection.execute(
                    """
                    SELECT result_json FROM tasks
                    WHERE stage='github-final-visibility-batch'
                    """
                ).fetchone()["result_json"])
                self.assertEqual(1, document["error_count"])
                self.assertEqual(1, document["points_used"])

    def test_final_visibility_resume_counts_prior_graphql_before_request(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = MutableVisibilityMetadata()

            def flip_private_after_scan(*args, **kwargs):
                outcomes = fake_scan_runner(*args, **kwargs)
                metadata.private = True
                return outcomes

            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=metadata,
                scan_runner=flip_private_after_scan,
                citation_pipeline=FakeCitationPipeline(),
            )
            budgets = dataclasses.replace(
                self.budgets(),
                max_graphql_points=2,
                min_graphql_remaining=0,
            )
            with self.assertRaises(PipelineError):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=budgets,
                )
            self.assertEqual(1, metadata.initial_calls)
            metadata.private = False
            pipeline.scan_runner = fake_scan_runner
            with self.assertRaisesRegex(
                BudgetExceeded, "same-run GitHub GraphQL point budget"
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=budgets,
                )
            self.assertEqual(1, metadata.initial_calls)

    def test_final_visibility_install_age_fails_closed(self):
        with self.assertRaisesRegex(PipelineError, "too old to install"):
            _assert_final_visibility_fresh({
                "checked_at": "2000-01-01T00:00:00Z",
            })

    def test_graphql_resume_ignores_expired_remaining_window(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.create_run("quota-window", mode="refresh")
                for ordinal, reset_at, remaining in (
                    (0, "2000-01-01T00:00:00Z", 2_501),
                    (1, "2999-01-01T00:00:00Z", 4_800),
                ):
                    task = state.enqueue_task(
                        "quota-window",
                        "github-metadata-batch",
                        "batch:%d" % ordinal,
                    )
                    state.lease_task_by_id(task, worker="fixture")
                    state.complete_task(
                        task,
                        worker="fixture",
                        result={
                            "version": 2,
                            "kind": "github-metadata-batch",
                            "repositories": [],
                            "error_count": 0,
                            "request_count": 1,
                            "points_used": 1,
                            "remaining": remaining,
                            "reset_at": reset_at,
                        },
                    )
                budget = _graphql_journal_budget(
                    state, "quota-window"
                )
                self.assertEqual(2, budget["points_used"])
                self.assertEqual(4_800, budget["remaining"])
                self.assertEqual(
                    "2999-01-01T00:00:00Z", budget["reset_at"]
                )

    def test_graphql_budget_charges_predecessor_lineage(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.create_run(
                    "graphql-lineage",
                    mode="reconcile",
                    plan={
                        "execution_contract": {
                            "historical_graphql_usage": {
                                "request_count": 774,
                                "points_used": 774,
                                "remaining": 4_388,
                                "reset_at": "2999-01-01T00:00:00Z",
                            },
                        },
                    },
                )
                task = state.enqueue_task(
                    "graphql-lineage",
                    "github-metadata-batch",
                    "batch:0",
                )
                state.lease_task_by_id(task, worker="fixture")
                state.complete_task(
                    task,
                    worker="fixture",
                    result={
                        "version": 2,
                        "kind": "github-metadata-batch",
                        "repositories": [],
                        "error_count": 0,
                        "request_count": 1,
                        "points_used": 1,
                        "remaining": 4_800,
                        "reset_at": "2999-01-01T00:00:00Z",
                    },
                )
                budget = _graphql_journal_budget(
                    state, "graphql-lineage"
                )
                self.assertEqual(775, budget["request_count"])
                self.assertEqual(775, budget["points_used"])
                self.assertEqual(4_388, budget["remaining"])
                self.assertEqual(
                    "2999-01-01T00:00:00Z", budget["reset_at"]
                )

    def test_final_visibility_checkpoint_round_trip_keeps_budget_not_private(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_path = root / "source.sqlite3"
            shards = root / "checkpoint"
            with StateDB(source_path) as state:
                state.upsert_repository({
                    "node_id": "R_public",
                    "full_name": "public/example",
                    "visibility": "public",
                    "is_fork": False,
                    "is_archived": False,
                })
                state.create_run("visibility-checkpoint", mode="refresh")
                task = state.enqueue_task(
                    "visibility-checkpoint",
                    "github-final-visibility-batch",
                    "epoch:fixture",
                    payload={
                        "lookups": [
                            {"node_id": "R_public", "full_name": None},
                            {"node_id": "R_private", "full_name": None},
                        ],
                    },
                )
                state.lease_task_by_id(task, worker="fixture")
                state.complete_task(
                    task,
                    worker="fixture",
                    result={
                        "version": 2,
                        "kind": "github-metadata-batch",
                        "repositories": [
                            {
                                "request_key": "node:R_public",
                                "requested_node_id": "R_public",
                                "requested_full_name": None,
                                "node_id": "R_public",
                                "full_name": "public/example",
                                "admitted_public": True,
                                "status": "ok",
                                "error_count": 0,
                            },
                            {
                                "request_key": "node:R_private",
                                "requested_node_id": "R_private",
                                "requested_full_name": None,
                                "admitted_public": False,
                                "status": "private",
                                "error_count": 0,
                            },
                        ],
                        "error_count": 0,
                        "request_count": 1,
                        "points_used": 7,
                        "remaining": 4_800,
                        "reset_at": "2999-01-01T00:00:00Z",
                    },
                )
                state.export_checkpoint_shards(shards)
            with StateDB(root / "restored.sqlite3") as restored:
                restored.import_checkpoint(shards)
                row = restored.connection.execute(
                    """
                    SELECT payload_json, result_json FROM tasks
                    WHERE stage='github-final-visibility-batch'
                    """
                ).fetchone()
                payload = json.loads(row["payload_json"])
                result = json.loads(row["result_json"])
                self.assertEqual(
                    [{"node_id": "R_public", "full_name": None}],
                    payload["lookups"],
                )
                self.assertEqual(1, len(result["repositories"]))
                self.assertEqual(7, result["points_used"])
                self.assertEqual(
                    7,
                    _graphql_journal_budget(
                        restored, "visibility-checkpoint"
                    )["points_used"],
                )

    def test_final_visibility_late_crash_resumes_exact_fresh_epoch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = MutableVisibilityMetadata()
            metadata.batch_size = 1
            ticks = iter((0.0, 100.0))
            pipeline = CollectorPipeline(
                repo_root=root,
                metadata=metadata,
                clock=lambda: next(ticks),
            )
            current = {
                "repos": [
                    {"repository_node_id": "R_a"},
                    {"repository_node_id": "R_b"},
                ],
            }
            initial = GraphQLResolution(
                (), (), 0, 0, 5_000, "2999-01-01T00:00:00Z"
            )
            with StateDB(root / "state.sqlite3") as state:
                state.create_run("late-crash", mode="refresh")
                with self.assertRaisesRegex(
                    BudgetExceeded, "wall-time budget exhausted"
                ):
                    pipeline._reattest_final_visibility(
                        state,
                        "late-crash",
                        current,
                        initial,
                        self.budgets(),
                        run_deadline=50,
                    )
                self.assertEqual(1, metadata.final_calls)
                self.assertEqual(
                    ["complete", "pending"],
                    [
                        row["status"]
                        for row in state.connection.execute(
                            """
                            SELECT status FROM tasks
                            WHERE run_id=? AND
                              stage='github-final-visibility-batch'
                            ORDER BY task_id
                            """,
                            ("late-crash",),
                        )
                    ],
                )
                pipeline.clock = lambda: 0.0
                attestation = pipeline._reattest_final_visibility(
                    state,
                    "late-crash",
                    current,
                    initial,
                    self.budgets(),
                    run_deadline=50,
                    allow_resume=True,
                )
                self.assertEqual(2, metadata.final_calls)
                self.assertEqual(1, attestation["tasks_reused"])
                self.assertEqual(2, attestation["graphql_points"])
                self.assertEqual(
                    2,
                    _graphql_journal_budget(
                        state, "late-crash"
                    )["points_used"],
                )
                with self.assertRaisesRegex(
                    PipelineError, "set changed"
                ):
                    pipeline._reattest_final_visibility(
                        state,
                        "late-crash",
                        {
                            "repos": [
                                {"repository_node_id": "R_a"},
                                {"repository_node_id": "R_c"},
                            ],
                        },
                        initial,
                        self.budgets(),
                        run_deadline=50,
                        allow_resume=True,
                    )
                self.assertEqual(2, metadata.final_calls)
                state.connection.execute(
                    """
                    UPDATE tasks
                    SET payload_json=replace(
                        payload_json, ?, ?
                    )
                    WHERE run_id=? AND
                      stage='github-final-visibility-batch'
                    """,
                    (
                        attestation["checked_at"],
                        "2000-01-01T00:00:00Z",
                        "late-crash",
                    ),
                )
                with self.assertRaisesRegex(
                    PipelineError, "epoch is stale"
                ):
                    pipeline._reattest_final_visibility(
                        state,
                        "late-crash",
                        current,
                        initial,
                        self.budgets(),
                        run_deadline=50,
                        allow_resume=True,
                    )
                self.assertEqual(2, metadata.final_calls)

    def test_failed_visibility_never_reuses_epoch_after_fresh_metadata(self):
        self.assertFalse(
            _should_resume_final_visibility_epoch(
                resumed_run=True,
                prior_stage_status="failed",
            )
        )
        self.assertTrue(
            _should_resume_final_visibility_epoch(
                resumed_run=True,
                prior_stage_status="running",
            )
        )
        self.assertTrue(
            _should_resume_final_visibility_epoch(
                resumed_run=True,
                prior_stage_status="complete",
            )
        )
        self.assertFalse(
            _should_resume_final_visibility_epoch(
                resumed_run=False,
                prior_stage_status="complete",
            )
        )

    def test_certified_newest_visibility_rejection_forces_fresh_metadata(self):
        self.assertTrue(
            _should_force_metadata_refresh_after_final_visibility(
                resumed_run=True,
                prior_stage_status="failed",
                reusable_fresh_metadata_epoch=True,
                visibility_rejection_resume_control={"version": 1},
            )
        )
        self.assertFalse(
            _should_force_metadata_refresh_after_final_visibility(
                resumed_run=True,
                prior_stage_status="failed",
                reusable_fresh_metadata_epoch=True,
                visibility_rejection_resume_control=None,
            )
        )

    def test_forced_refresh_never_resumes_prior_partial_epoch(self):
        self.assertFalse(
            _should_resume_incomplete_fresh_metadata_epoch(
                force_metadata_refresh=True,
                graphql_resume_control={"version": 1},
            )
        )
        self.assertTrue(
            _should_resume_incomplete_fresh_metadata_epoch(
                force_metadata_refresh=False,
                graphql_resume_control={"version": 1},
            )
        )

    def test_production_rejects_invalid_metadata_batch_size_before_network(self):
        with self.assertRaisesRegex(
            ValueError, "invalid production metadata batch size"
        ):
            CollectorPipeline.production(metadata_batch_size=101)

    def test_graphql_journal_charges_malformed_response_reserve(self):
        with tempfile.TemporaryDirectory() as td:
            with StateDB(Path(td) / "state.sqlite3") as state:
                state.create_run(
                    "reserved",
                    mode="reconcile",
                    plan={
                        "execution_contract": {
                            "visibility_transport_retry_control": {
                                "reserved_unobserved_points": 1,
                                "failed_attempt_count": 1,
                            }
                        }
                    },
                    status="failed",
                )
                self.assertEqual(
                    {
                        "request_count": 1,
                        "points_used": 1,
                        "remaining": None,
                        "reset_at": None,
                    },
                    _graphql_journal_budget(state, "reserved"),
                )

    def test_graphql_journal_charges_epoch_recovery_reserve(self):
        with tempfile.TemporaryDirectory() as td:
            with StateDB(Path(td) / "state.sqlite3") as state:
                state.create_run(
                    "recovered",
                    mode="reconcile",
                    plan={
                        "execution_contract": {
                            "visibility_transport_retry_control": {
                                "reserved_unobserved_points": 1,
                                "failed_attempt_count": 1,
                            },
                            "visibility_epoch_recovery_control": {
                                "additional_reserved_unobserved_points": 1,
                                "additional_failed_attempt_count": 1,
                            },
                        }
                    },
                    status="failed",
                )
                budget = _graphql_journal_budget(state, "recovered")
                self.assertEqual(2, budget["request_count"])
                self.assertEqual(2, budget["points_used"])

    def test_crash_after_final_attestation_reuses_it_before_install(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = MutableVisibilityMetadata()
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=metadata,
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            budgets = dataclasses.replace(
                self.budgets(),
                max_graphql_points=2,
                min_graphql_remaining=0,
            )
            with mock.patch(
                "collector.pipeline._assert_final_visibility_fresh",
                side_effect=OSError("crash after final attestation"),
            ):
                with self.assertRaisesRegex(
                    OSError, "crash after final attestation"
                ):
                    pipeline.run(
                        mode="onboard",
                        library_ids=("cublas",),
                        budgets=budgets,
                    )
            self.assertEqual(1, metadata.initial_calls)
            self.assertEqual(1, metadata.final_calls)
            self.assertFalse((root / "data/v2/manifest.json").exists())
            with StateDB(root / ".state/collector.sqlite3") as state:
                run_id = state.connection.execute(
                    "SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1"
                ).fetchone()["run_id"]
                self.assertEqual(
                    "complete",
                    state.connection.execute(
                        """
                        SELECT status FROM stages
                        WHERE run_id=? AND stage='final_visibility'
                        """,
                        (run_id,),
                    ).fetchone()["status"],
                )
            result = pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=budgets,
            )
            self.assertEqual(run_id, result["run_id"])
            self.assertEqual(1, metadata.initial_calls)
            self.assertEqual(1, metadata.final_calls)
            self.assertEqual(
                1,
                result["report"]["api"]["final_visibility"][
                    "tasks_reused"
                ],
            )
            self.assertTrue((root / "data/v2/manifest.json").exists())

    def test_planner_models_both_graphql_passes_at_30k_and_60k(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            cold = build_plan(
                mode="reconcile",
                state_path=root / ".state/collector.sqlite3",
                data_dir=root / "data",
            )
            self.assertEqual(600, cold.estimated_initial_graphql_requests)
            self.assertEqual(
                600, cold.estimated_final_visibility_graphql_requests
            )
            self.assertEqual(1_200, cold.estimated_graphql_requests)
            counts = {
                **cold.local_counts,
                "known_repositories": 60_000,
                "legacy_published_repositories": 60_000,
            }
            with mock.patch(
                "collector.planner._local_counts",
                return_value=counts,
            ):
                large = build_plan(
                    mode="reconcile",
                    state_path=root / ".state/collector.sqlite3",
                    data_dir=root / "data",
                )
            self.assertEqual(
                1_200, large.estimated_initial_graphql_requests
            )
            self.assertEqual(
                1_200,
                large.estimated_final_visibility_graphql_requests,
            )
            self.assertEqual(2_400, large.estimated_graphql_requests)
            self.assertLessEqual(
                large.estimated_final_visibility_minutes, 120
            )
            over_counts = {
                **counts,
                "known_repositories": 65_000,
                "legacy_published_repositories": 65_000,
            }
            with mock.patch(
                "collector.planner._local_counts",
                return_value=over_counts,
            ):
                refused = build_plan(
                    mode="reconcile",
                    state_path=root / ".state/collector.sqlite3",
                    data_dir=root / "data",
                )
            self.assertTrue(any(
                "exceeds point budget" in reason
                for reason in refused.reasons
            ))
            self.assertTrue(any(
                "cross remaining-quota reserve" in reason
                for reason in refused.reasons
            ))

    def test_changed_live_base_refuses_resume_before_network(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            first_sourcegraph = FakeDiscovery("sourcegraph")
            first_github = CrashOnceDiscovery("github-code-search")
            first = CollectorPipeline(
                repo_root=root,
                sourcegraph=first_sourcegraph,
                github_search=first_github,
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            budgets = self.budgets()
            with self.assertRaises(OSError):
                first.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=budgets,
                )
            live = root / "data/v2"
            live.mkdir()
            (live / "manifest.json").write_text(
                '{"release":{"id":"changed-live-release"}}\n'
            )
            sourcegraph = mock.Mock()
            github = mock.Mock()
            metadata = mock.Mock()
            second = CollectorPipeline(
                repo_root=root,
                sourcegraph=sourcegraph,
                github_search=github,
                metadata=metadata,
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            with self.assertRaisesRegex(
                PipelineError, "incompatible interrupted run"
            ):
                second.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=budgets,
                )
            sourcegraph.search.assert_not_called()
            github.search.assert_not_called()
            metadata.resolve.assert_not_called()

    def test_metadata_task_journal_sanitizes_nonpublic_resolution(self):
        class PrivateMetadata:
            batch_size = 50

            def resolve(self, lookups, **_kwargs):
                lookup = list(lookups)[0]
                return GraphQLResolution(
                    (
                        RepositoryMetadata(
                            request_key=lookup.key,
                            requested_node_id=lookup.node_id,
                            requested_full_name=lookup.full_name,
                            node_id="R_private",
                            full_name="private/renamed",
                            visibility="PRIVATE",
                            is_private=True,
                            is_fork=False,
                            is_archived=False,
                            default_branch="main",
                            head_oid="d" * 40,
                            renamed=True,
                            status="private",
                            errors=(
                                "repository private/renamed is inaccessible",
                            ),
                        ),
                    ),
                    (
                        GraphQLError(
                            "private/renamed cannot be queried",
                            lookup.key,
                            "FORBIDDEN",
                        ),
                    ),
                    1,
                    1,
                    4_999,
                    "2026-07-27T17:00:00Z",
                )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            pipeline = CollectorPipeline(
                repo_root=root,
                metadata=PrivateMetadata(),
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                state.create_run(
                    "private-filter",
                    mode="refresh",
                    base_release_id=NO_LIVE_V2_RELEASE,
                    status="running",
                )
                resolution, publishable, _by_name, _by_node = (
                    pipeline._resolve_metadata(
                        state,
                        (),
                        {"public/was-public": {"cublas"}},
                        (),
                        run_id="private-filter",
                        budgets=self.budgets(),
                    )
                )
                self.assertTrue(resolution.complete)
                self.assertEqual({}, publishable)
                task = state.connection.execute(
                    """
                    SELECT result_json, status FROM tasks
                    WHERE run_id='private-filter'
                      AND stage='github-metadata-batch'
                    """
                ).fetchone()
                self.assertEqual("complete", task["status"])
                self.assertNotIn("private/renamed", task["result_json"])
                self.assertNotIn("inaccessible", task["result_json"])
                self.assertNotIn("FORBIDDEN", task["result_json"])
                self.assertNotIn('"visibility"', task["result_json"])
                self.assertNotIn('"is_private"', task["result_json"])
                self.assertEqual(
                    1, json.loads(task["result_json"])["error_count"]
                )
                self.assertNotIn('"errors"', task["result_json"])

    def test_aggregation_crash_restarts_without_repeating_durable_work(self):
        class InjectedAggregationCrash(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            sourcegraph = FakeDiscovery("sourcegraph")
            github = FakeDiscovery("github-code-search")
            scan_invocations = []

            def counted_scan_runner(*args, **kwargs):
                scan_invocations.append("scan")
                return fake_scan_runner(*args, **kwargs)

            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=sourcegraph,
                github_search=github,
                metadata=FakeMetadata(),
                scan_runner=counted_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            with mock.patch.object(
                pipeline,
                "_materialize",
                side_effect=InjectedAggregationCrash(
                    "synthetic aggregation crash"
                ),
            ), self.assertRaisesRegex(
                InjectedAggregationCrash,
                "synthetic aggregation crash",
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=self.budgets(),
                )

            source_calls = (sourcegraph.calls, github.calls)
            with StateDB(root / ".state/collector.sqlite3") as state:
                interrupted = state.connection.execute(
                    """
                    SELECT run_id, status FROM runs
                    ORDER BY created_at DESC, run_id DESC LIMIT 1
                    """
                ).fetchone()
                aggregation = state.connection.execute(
                    """
                    SELECT status FROM stages
                    WHERE run_id=? AND stage='aggregation'
                    """,
                    (interrupted["run_id"],),
                ).fetchone()
                scan_tasks = state.connection.execute(
                    """
                    SELECT status, COUNT(*) AS count FROM tasks
                    WHERE run_id=? AND stage='scan' GROUP BY status
                    """,
                    (interrupted["run_id"],),
                ).fetchall()
            self.assertEqual("failed", interrupted["status"])
            self.assertEqual("failed", aggregation["status"])
            self.assertEqual(
                {"complete": 1},
                {row["status"]: row["count"] for row in scan_tasks},
            )
            self.assertFalse((root / "data/v2").exists())

            recovered = pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self.budgets(),
            )
            self.assertEqual(interrupted["run_id"], recovered["run_id"])
            self.assertEqual(source_calls, (sourcegraph.calls, github.calls))
            self.assertEqual(["scan"], scan_invocations)
            with StateDB(root / ".state/collector.sqlite3") as state:
                aggregation = state.connection.execute(
                    """
                    SELECT status FROM stages
                    WHERE run_id=? AND stage='aggregation'
                    """,
                    (recovered["run_id"],),
                ).fetchone()
            self.assertEqual("complete", aggregation["status"])

    def test_redating_crash_rolls_back_and_restarts_from_durable_evidence(self):
        class InjectedRedatingCrash(RuntimeError):
            pass

        fingerprints = {
            "discovery": "a" * 64,
            "detector": "b" * 64,
            "citation": "c" * 64,
            "dating": "old-dating",
            "aggregation": "d" * 64,
            "presentation": "e" * 64,
            "release": "f" * 64,
        }
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.sqlite3"
            pipeline = CollectorPipeline(repo_root=Path(td))
            with StateDB(state_path) as state:
                state.upsert_library(
                    "cublas",
                    catalog={"name": "cuBLAS"},
                    fingerprints=fingerprints,
                )
                state.upsert_repository(
                    {
                        "node_id": "R_public",
                        "full_name": "public/example",
                        "visibility": "public",
                        "head_sha": "a" * 40,
                    }
                )
                scan_result_id = state.record_scan_result(
                    repository_id="R_public",
                    library_id="cublas",
                    head_sha="a" * 40,
                    detector_fp="b" * 64,
                    classification="confirmed",
                    status="clean",
                    evidence={
                        "classification": "confirmed",
                        "first_integration": "2020-01-02",
                        "_dating_fp": "old-dating",
                    },
                    raw_first_commit="1" * 40,
                    raw_first_date="2020-01-02",
                    derived_first_date="2020-01-02",
                )
                state.create_run(
                    "redate-restart",
                    mode="refresh",
                    status="running",
                )

                def crash_completion(
                    _state,
                    _task_id,
                    *,
                    worker,
                    result=None,
                    now_epoch=None,
                ):
                    del worker, result, now_epoch
                    raise InjectedRedatingCrash(
                        "synthetic redating journal crash"
                    )

                with mock.patch.object(
                    StateDB,
                    "complete_task",
                    autospec=True,
                    side_effect=crash_completion,
                ), self.assertRaisesRegex(
                    InjectedRedatingCrash,
                    "synthetic redating journal crash",
                ):
                    pipeline._redate(
                        state,
                        "redate-restart",
                        "new-dating",
                    )

                after_crash = state.connection.execute(
                    """
                    SELECT evidence_json, derived_first_date
                    FROM scan_results WHERE scan_result_id=?
                    """,
                    (scan_result_id,),
                ).fetchone()
                task_after_crash = state.connection.execute(
                    """
                    SELECT status, attempts FROM tasks
                    WHERE run_id='redate-restart' AND stage='redate'
                    """
                ).fetchone()
                self.assertEqual(
                    "old-dating",
                    json.loads(after_crash["evidence_json"])["_dating_fp"],
                )
                self.assertEqual("2020-01-02", after_crash["derived_first_date"])
                self.assertEqual(
                    ("running", 1),
                    (task_after_crash["status"], task_after_crash["attempts"]),
                )

            with StateDB(state_path) as restarted:
                self.assertEqual(
                    1, restarted.recover_stale_tasks(now_epoch=10**12)
                )
                self.assertEqual(
                    1,
                    pipeline._redate(
                        restarted,
                        "redate-restart",
                        "new-dating",
                    ),
                )
                recovered = restarted.connection.execute(
                    """
                    SELECT evidence_json, derived_first_date
                    FROM scan_results WHERE scan_result_id=?
                    """,
                    (scan_result_id,),
                ).fetchone()
                recovered_task = restarted.connection.execute(
                    """
                    SELECT status, attempts, result_json FROM tasks
                    WHERE run_id='redate-restart' AND stage='redate'
                    """
                ).fetchone()
            self.assertEqual(
                "new-dating",
                json.loads(recovered["evidence_json"])["_dating_fp"],
            )
            self.assertEqual("2020-01-02", recovered["derived_first_date"])
            self.assertEqual(
                ("complete", 2, "redated"),
                (
                    recovered_task["status"],
                    recovered_task["attempts"],
                    json.loads(recovered_task["result_json"])["status"],
                ),
            )

    def test_network_task_lease_is_sub_ten_minute_and_reclaimable(self):
        self.assertLess(NETWORK_TASK_LEASE_SECONDS, 600)
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.create_run(
                    "crashed",
                    mode="refresh",
                    base_release_id=NO_LIVE_V2_RELEASE,
                    status="running",
                )
                task_id = state.enqueue_task(
                    "crashed",
                    "discovery-query",
                    "sg:cublas:fixture",
                    payload={"source": "sourcegraph"},
                )
                leased = state.lease_task_by_id(
                    task_id,
                    worker="dead-coordinator",
                    lease_seconds=NETWORK_TASK_LEASE_SECONDS,
                    now_epoch=100,
                )
                self.assertEqual("running", leased["status"])
                self.assertEqual(
                    100 + NETWORK_TASK_LEASE_SECONDS,
                    leased["lease_expires_at"],
                )
                self.assertEqual(
                    0,
                    state.recover_stale_tasks(
                        now_epoch=(
                            100 + NETWORK_TASK_LEASE_SECONDS - 1
                        )
                    ),
                )
                self.assertEqual(
                    1,
                    state.recover_stale_tasks(
                        now_epoch=(
                            100 + NETWORK_TASK_LEASE_SECONDS + 1
                        )
                    ),
                )
                recovered = state.connection.execute(
                    "SELECT status, attempts FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()
                self.assertEqual("pending", recovered["status"])
                self.assertEqual(1, recovered["attempts"])

    def test_network_task_heartbeat_renews_slow_task_past_initial_expiry(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.create_run("slow", mode="refresh", status="running")
                task_id = state.enqueue_task(
                    "slow",
                    "discovery-query",
                    "sg:cublas:slow",
                    payload={"source": "sourcegraph"},
                )
                lease_seconds = 0.30
                leased = state.lease_task_by_id(
                    task_id,
                    worker="slow-worker",
                    lease_seconds=lease_seconds,
                )
                initial_expiry = float(leased["lease_expires_at"])
                heartbeat = _TaskLeaseHeartbeat(
                    state_path,
                    task_id,
                    "slow-worker",
                    lease_seconds,
                    interval_seconds=0.04,
                )
                heartbeat.start()
                try:
                    deadline = time.monotonic() + 2.0
                    renewed_expiry = initial_expiry
                    while (
                        renewed_expiry < initial_expiry + 0.12
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.02)
                        renewed_expiry = float(
                            state.connection.execute(
                                """
                                SELECT lease_expires_at FROM tasks
                                WHERE task_id=?
                                """,
                                (task_id,),
                            ).fetchone()["lease_expires_at"]
                        )
                    self.assertGreaterEqual(
                        renewed_expiry, initial_expiry + 0.12
                    )
                    wait = initial_expiry + 0.02 - time.time()
                    if wait > 0:
                        time.sleep(wait)
                    active = state.connection.execute(
                        """
                        SELECT status, lease_expires_at FROM tasks
                        WHERE task_id=?
                        """,
                        (task_id,),
                    ).fetchone()
                    self.assertGreater(time.time(), initial_expiry)
                    self.assertEqual("running", active["status"])
                    self.assertGreater(
                        active["lease_expires_at"], time.time()
                    )
                    heartbeat.verify(state)
                finally:
                    heartbeat.stop()
                state.complete_task(
                    task_id,
                    worker="slow-worker",
                    result={"status": "complete"},
                )

    def test_network_task_heartbeat_prevents_duplicate_reclaim(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.create_run("owned", mode="refresh", status="running")
                task_id = state.enqueue_task(
                    "owned",
                    "github-metadata-batch",
                    "batch:owned",
                    payload={"lookups": []},
                )
                lease_seconds = 0.30
                leased = state.lease_task_by_id(
                    task_id,
                    worker="original-worker",
                    lease_seconds=lease_seconds,
                )
                initial_expiry = float(leased["lease_expires_at"])
                heartbeat = _TaskLeaseHeartbeat(
                    state_path,
                    task_id,
                    "original-worker",
                    lease_seconds,
                    interval_seconds=0.04,
                )
                heartbeat.start()
                try:
                    deadline = time.monotonic() + 2.0
                    renewed_expiry = initial_expiry
                    while (
                        renewed_expiry <= initial_expiry + 0.08
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.02)
                        renewed_expiry = float(
                            state.connection.execute(
                                "SELECT lease_expires_at FROM tasks WHERE task_id=?",
                                (task_id,),
                            ).fetchone()["lease_expires_at"]
                        )
                    self.assertGreater(
                        renewed_expiry, initial_expiry + 0.08
                    )
                    with StateDB(state_path) as contender:
                        reclaim_at = initial_expiry + 0.05
                        self.assertEqual(
                            0,
                            contender.recover_stale_tasks(
                                now_epoch=reclaim_at
                            ),
                        )
                        self.assertIsNone(
                            contender.lease_task_by_id(
                                task_id,
                                worker="duplicate-worker",
                                lease_seconds=lease_seconds,
                                now_epoch=reclaim_at,
                            )
                        )
                    heartbeat.verify(state)
                finally:
                    heartbeat.stop()
                state.complete_task(
                    task_id,
                    worker="original-worker",
                    result={"status": "complete"},
                )
                row = state.connection.execute(
                    "SELECT status, attempts FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()
                self.assertEqual(("complete", 1), tuple(row))

    def test_network_task_heartbeat_fails_closed_after_lease_loss(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.sqlite3"
            with StateDB(state_path) as state:
                state.create_run("lost", mode="refresh", status="running")
                task_id = state.enqueue_task(
                    "lost",
                    "discovery-query",
                    "sg:cublas:lost",
                    payload={"source": "sourcegraph"},
                )
                state.lease_task_by_id(
                    task_id,
                    worker="original-worker",
                    lease_seconds=30,
                )
                heartbeat = _TaskLeaseHeartbeat(
                    state_path,
                    task_id,
                    "original-worker",
                    30,
                    interval_seconds=5,
                )
                heartbeat.start()
                try:
                    state.connection.execute(
                        """
                        UPDATE tasks SET lease_owner='replacement-worker'
                        WHERE task_id=?
                        """,
                        (task_id,),
                    )
                    with self.assertRaisesRegex(
                        PipelineError,
                        "journaled network task lease was lost",
                    ):
                        heartbeat.verify(state)
                finally:
                    heartbeat.stop()
                row = state.connection.execute(
                    "SELECT status, lease_owner FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()
                self.assertEqual(
                    ("running", "replacement-worker"), tuple(row)
                )

    def test_discovery_and_metadata_tasks_use_task_heartbeats(self):
        events = []

        class RecordingHeartbeat:
            def __init__(
                self,
                _state_path,
                task_id,
                worker,
                lease_seconds,
            ):
                self.task_id = task_id
                self.worker = worker
                self.lease_seconds = lease_seconds

            def start(self):
                events.append(("start", self.task_id))

            def verify(self, _state):
                events.append(("verify", self.task_id))

            def stop(self):
                events.append(("stop", self.task_id))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            with mock.patch(
                "collector.pipeline._TaskLeaseHeartbeat",
                RecordingHeartbeat,
            ):
                result = pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=self.budgets(),
                )
            with StateDB(root / ".state/collector.sqlite3") as state:
                task_ids = {
                    row["task_id"]
                    for row in state.connection.execute(
                        """
                        SELECT task_id FROM tasks
                        WHERE run_id=? AND stage IN (
                            'discovery-query', 'github-metadata-batch',
                            'github-final-visibility-batch'
                        )
                        """,
                        (result["run_id"],),
                    )
                }
            for action in ("start", "verify", "stop"):
                self.assertEqual(
                    task_ids,
                    {
                        task_id
                        for event, task_id in events
                        if event == action
                    },
                )
                self.assertEqual(
                    len(task_ids),
                    sum(event == action for event, _task_id in events),
                )

    def test_pipeline_preserves_missing_disk_usage_as_unknown_scan_size(self):
        captured = []

        def capture_runner(tasks, *args, **kwargs):
            captured.extend(tasks)
            return fake_scan_runner(tasks, *args, **kwargs)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=capture_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self.budgets(),
            )

        self.assertEqual(1, len(captured))
        self.assertIsNone(captured[0].estimated_size)

    def test_changed_head_scan_task_carries_prior_first_use_boundaries(self):
        captured = []

        def capture_runner(tasks, *args, **kwargs):
            captured.extend(tasks)
            return fake_scan_runner(tasks, *args, **kwargs)

        boundary = {
            "primary": {
                "version": 1,
                "commit": "b" * 40,
                "date": "2020-01-01",
                "plan_signature": "c" * 64,
                "anchor": "cublas_v2.h",
                "evidence_path": "src/example.cu",
                "confirmed": True,
                "cpp_header_pattern": "cublas_v2\\.h",
            }
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=capture_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            pipeline._active_plan = build_plan(
                mode="onboard",
                state_path=root / "state.sqlite3",
                data_dir=root / "data",
                libraries=[
                    next(
                        lib for lib in LIBRARIES
                        if lib["id"] == "cublas"
                    )
                ],
            )
            effective_fp = _library_fp_values(
                pipeline._active_plan, "cublas"
            )["detector"]
            with StateDB(root / "state.sqlite3") as state:
                state.upsert_library(
                    "cublas",
                    catalog={"name": "cuBLAS"},
                    fingerprints={
                        "discovery": "f" * 64,
                        "detector": effective_fp,
                        "citation": "f" * 64,
                        "dating": "e" * 64,
                        "aggregation": "f" * 64,
                        "presentation": "f" * 64,
                        "release": "f" * 64,
                    },
                )
                state.connection.execute(
                    "UPDATE libraries SET detector_fp=? WHERE library_id=?",
                    ("f" * 64, "cublas"),
                )
                state.upsert_repository({
                    "node_id": "R_public_example",
                    "full_name": "public/example",
                    "visibility": "public",
                    "default_branch": "main",
                    "head_sha": "a" * 40,
                })
                state.record_scan_result(
                    repository_id="R_public_example",
                    library_id="cublas",
                    head_sha="b" * 40,
                    detector_fp=effective_fp,
                    classification="confirmed",
                    status="clean",
                    evidence={
                        "classification": "confirmed",
                        "first_integration": "2020-01-01",
                        "first_integration_commit": "b" * 12,
                        "_first_use_boundaries": boundary,
                    },
                )
                state.create_run(
                    "changed-head",
                    mode="onboard",
                    status="running",
                )
                item = RepositoryMetadata(
                    request_key="node:R_public_example",
                    requested_node_id="R_public_example",
                    requested_full_name="public/example",
                    node_id="R_public_example",
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
                pipeline._scan(
                    state,
                    "changed-head",
                    [
                        next(
                            lib
                            for lib in LIBRARIES
                            if lib["id"] == "cublas"
                        )
                    ],
                    {"public/example": {"cublas"}},
                    {"public/example": item},
                    self.budgets(),
                )
                recorded_fp = state.connection.execute(
                    """
                    SELECT detector_fp FROM scan_results
                    WHERE repository_id=? AND head_sha=?
                    ORDER BY scan_result_id DESC LIMIT 1
                    """,
                    ("R_public_example", "a" * 40),
                ).fetchone()[0]
        self.assertEqual(1, len(captured))
        self.assertEqual(
            boundary,
            json.loads(
                dict(captured[0].prior_first_use_boundaries)[
                    "cublas"
                ]
            ),
        )
        self.assertEqual(effective_fp, recorded_fp)

    def test_owner_control_defers_exact_fresh_candidate_without_scan_task(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            library = next(
                item for item in LIBRARIES if item["id"] == "cublas"
            )
            pipeline._active_plan = build_plan(
                mode="onboard",
                state_path=root / "state.sqlite3",
                data_dir=root / "data",
                libraries=[library],
            )
            item = RepositoryMetadata(
                request_key="node:R_fresh",
                requested_node_id="R_fresh",
                requested_full_name="public/fresh",
                node_id="R_fresh",
                full_name="public/fresh",
                visibility="PUBLIC",
                is_private=False,
                is_fork=False,
                is_archived=False,
                default_branch="main",
                head_oid="a" * 40,
                renamed=False,
                status="ok",
            )
            detector = _library_fp_values(
                pipeline._active_plan, "cublas"
            )["detector"]
            task_key = fingerprint(
                "scan-task-v2",
                {
                    "repository_node_id": item.node_id,
                    "head_sha": item.head_oid,
                    "candidate_library_ids": ["cublas"],
                    "analysis_only": False,
                    "ai_fingerprint": None,
                    "detector_fingerprints": {"cublas": detector},
                },
            )
            proof = [{
                "task_key": task_key,
                "repository_identity_sha256": hashlib.sha256(
                    b"R_fresh\0public/fresh"
                ).hexdigest(),
                "libraries": ["cublas"],
            }]
            with StateDB(root / "state.sqlite3") as state:
                state.upsert_repository({
                    "node_id": item.node_id,
                    "full_name": item.full_name,
                    "visibility": "public",
                    "default_branch": "main",
                    "head_sha": item.head_oid,
                })
                state.create_run("fresh", mode="onboard", status="running")
                outcomes, scanned = pipeline._scan(
                    state,
                    "fresh",
                    [library],
                    {item.full_name: {"cublas"}},
                    {item.full_name: item},
                    self.budgets(),
                    preserve_task_universe=True,
                    fresh_candidate_deferral_control={
                        "deferred_task_proof": proof
                    },
                )
                self.assertEqual(([], 0), (outcomes, scanned))
                self.assertEqual(
                    0,
                    state.connection.execute(
                        "SELECT COUNT(*) FROM tasks WHERE run_id='fresh'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    1,
                    pipeline._scan_selection_metrics[
                        "fresh_candidate_deferred_tasks"
                    ],
                )
                changed = json.loads(json.dumps(proof))
                changed[0]["repository_identity_sha256"] = "0" * 64
                with self.assertRaisesRegex(
                    PipelineError, "deferral proof changed"
                ):
                    pipeline._scan(
                        state,
                        "fresh",
                        [library],
                        {item.full_name: {"cublas"}},
                        {item.full_name: item},
                        self.budgets(),
                        preserve_task_universe=True,
                        fresh_candidate_deferral_control={
                            "deferred_task_proof": changed
                        },
                    )

    def test_post_refresh_control_defers_one_promoted_fresh_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
            )
            library = next(
                item for item in LIBRARIES if item["id"] == "cublas"
            )
            pipeline._active_plan = build_plan(
                mode="onboard",
                state_path=root / "state.sqlite3",
                data_dir=root / "data",
                libraries=[library],
            )
            item = RepositoryMetadata(
                request_key="name:public/promoted",
                requested_node_id=None,
                requested_full_name="public/promoted",
                node_id="R_promoted",
                full_name="public/promoted",
                visibility="PUBLIC",
                is_private=False,
                is_fork=False,
                is_archived=False,
                default_branch="main",
                head_oid="a" * 40,
                renamed=False,
                status="ok",
            )
            epoch = "8" * 16
            with StateDB(root / "state.sqlite3") as state:
                state.upsert_repository({
                    "node_id": item.node_id,
                    "full_name": item.full_name,
                    "visibility": "public",
                    "default_branch": "main",
                    "head_sha": item.head_oid,
                })
                state.create_run(
                    "fresh", mode="onboard", status="running"
                )
                payload = {
                    "version": 1,
                    "lookups": [{
                        "node_id": None,
                        "full_name": item.full_name,
                    }],
                }
                task_id = state.enqueue_task(
                    "fresh",
                    "github-metadata-batch",
                    "fresh:%s:batch:000000:fixture" % epoch,
                    payload=payload,
                )
                leased = state.lease_task_by_id(
                    task_id, worker="fixture", lease_seconds=300
                )
                self.assertIsNotNone(leased)
                state.complete_task(
                    task_id,
                    worker="fixture",
                    result=_metadata_result_to_task_result(
                        GraphQLResolution(
                            (item,), (), 1, 1, 4999, None
                        )
                    ),
                )
                outcomes, scanned = pipeline._scan(
                    state,
                    "fresh",
                    [library],
                    {item.full_name: {"cublas"}},
                    {item.full_name: item},
                    self.budgets(),
                    preserve_task_universe=True,
                    fresh_candidate_deferral_control={
                        "deferred_task_proof": []
                    },
                    post_refresh_privacy_control={
                        "fresh_metadata_epoch": epoch,
                        "fresh_metadata_batch_count": 1,
                    },
                )
                scan_task_count = state.connection.execute(
                    """
                    SELECT COUNT(*) FROM tasks
                    WHERE run_id='fresh' AND stage='scan'
                    """
                ).fetchone()[0]
            self.assertEqual(([], 0), (outcomes, scanned))
            self.assertEqual(0, scan_task_count)
            self.assertEqual(
                1,
                pipeline._scan_selection_metrics[
                    "post_refresh_deferred_tasks"
                ],
            )

    def test_dating_fingerprint_change_is_state_only_redating_work(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            first_pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            first_pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self.budgets(),
            )

            state_path = root / ".state/collector.sqlite3"
            old_dating_fp = "0" * 64
            with StateDB(state_path) as state:
                run = state.connection.execute(
                    """
                    SELECT run_id, fingerprints_json FROM runs
                    WHERE status='complete'
                    ORDER BY finished_at DESC, created_at DESC LIMIT 1
                    """
                ).fetchone()
                prior_fingerprints = json.loads(run["fingerprints_json"])
                prior_fingerprints["dating"] = old_dating_fp
                state.connection.execute(
                    "UPDATE runs SET fingerprints_json=? WHERE run_id=?",
                    (
                        json.dumps(
                            prior_fingerprints,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        run["run_id"],
                    ),
                )
                state.connection.execute(
                    "UPDATE libraries SET dating_fp=?",
                    (old_dating_fp,),
                )
                scan_row = state.connection.execute(
                    """
                    SELECT * FROM scan_results
                    WHERE repository_id='R_public_example'
                      AND library_id='cublas'
                    """
                ).fetchone()
                evidence = json.loads(scan_row["evidence_json"])
                evidence["_dating_fp"] = old_dating_fp
                state.connection.execute(
                    """
                    UPDATE scan_results SET evidence_json=?
                    WHERE scan_result_id=?
                    """,
                    (
                        json.dumps(
                            evidence,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        scan_row["scan_result_id"],
                    ),
                )
                state.connection.commit()
                before = dict(state.connection.execute(
                    """
                    SELECT * FROM scan_results
                    WHERE scan_result_id=?
                    """,
                    (scan_row["scan_result_id"],),
                ).fetchone())
                before_public_evidence = {
                    key: value
                    for key, value in json.loads(
                        before["evidence_json"]
                    ).items()
                    if not key.startswith("_")
                }

            forbidden_scan = mock.Mock(
                side_effect=AssertionError(
                    "dating-only invalidation entered scanner/cache path"
                )
            )
            second_pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=forbidden_scan,
                citation_pipeline=FakeCitationPipeline(),
            )
            result = second_pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self.budgets(),
            )

            self.assertTrue(
                result["plan"]["invalidation"]["redate_all_positives"]
            )
            self.assertEqual(1, result["redated"])
            self.assertEqual(0, result["scanned"])
            forbidden_scan.assert_not_called()
            self.assertFalse((root / ".state/git-cache").exists())
            with StateDB(state_path) as state:
                tasks = state.connection.execute(
                    """
                    SELECT stage, status, repository_id, library_id, result_json
                    FROM tasks
                    WHERE run_id=? AND stage='redate'
                    ORDER BY task_id
                    """,
                    (result["run_id"],),
                ).fetchall()
                self.assertEqual(1, len(tasks))
                self.assertEqual(
                    ("redate", "complete", "R_public_example", "cublas"),
                    (
                        tasks[0]["stage"],
                        tasks[0]["status"],
                        tasks[0]["repository_id"],
                        tasks[0]["library_id"],
                    ),
                )
                self.assertEqual(
                    "redated", json.loads(tasks[0]["result_json"])["status"]
                )
                stage = state.connection.execute(
                    """
                    SELECT status, counters_json FROM stages
                    WHERE run_id=? AND stage='redate'
                    """,
                    (result["run_id"],),
                ).fetchone()
                self.assertEqual("complete", stage["status"])
                self.assertEqual(
                    {"redated": 1}, json.loads(stage["counters_json"])
                )
                after = dict(state.connection.execute(
                    """
                    SELECT * FROM scan_results
                    WHERE scan_result_id=?
                    """,
                    (before["scan_result_id"],),
                ).fetchone())
                after_evidence = json.loads(after["evidence_json"])
                after_public_evidence = {
                    key: value
                    for key, value in after_evidence.items()
                    if not key.startswith("_")
                }
                self.assertEqual(before_public_evidence, after_public_evidence)
                for key in (
                    "repository_id",
                    "library_id",
                    "head_sha",
                    "detector_fp",
                    "classification",
                    "status",
                    "raw_first_commit",
                    "raw_first_date",
                    "scanned_at",
                ):
                    self.assertEqual(before[key], after[key])
                self.assertEqual(
                    after["raw_first_date"], after["derived_first_date"]
                )
                self.assertEqual(
                    result["plan"]["fingerprints"]["dating"],
                    after_evidence["_dating_fp"],
                )

    def test_complete_epoch_clean_reject_retires_and_rediscovery_reactivates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=clean_reject_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self.budgets(),
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                rows = state.connection.execute(
                    """
                    SELECT * FROM candidates
                    WHERE repository_id='R_public_example'
                      AND library_id='cublas'
                    ORDER BY candidate_id
                    """
                ).fetchall()
                self.assertTrue(rows)
                self.assertEqual({"rejected"}, {row["state"] for row in rows})
                row = rows[0]
                state.add_candidate(
                    repository_id=row["repository_id"],
                    library_id=row["library_id"],
                    source=row["source"],
                    query_fp=row["query_fp"],
                    coverage_epoch="rediscovered",
                    signal=row["signal"],
                    path=row["path"],
                    ref=row["ref"],
                )
                active = state.connection.execute(
                    "SELECT state FROM candidates WHERE candidate_id=?",
                    (row["candidate_id"],),
                ).fetchone()
                self.assertEqual("active", active["state"])

    def test_inexact_scan_outcomes_preserve_prior_manifest_bytes(self):
        for runner in (missing_scan_runner, duplicate_scan_runner):
            with self.subTest(runner=runner.__name__):
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    live = root / "data/v2"
                    live.mkdir(parents=True)
                    prior = b'{"release":{"id":"prior-release"}}\n'
                    (live / "manifest.json").write_bytes(prior)
                    pipeline = CollectorPipeline(
                        repo_root=root,
                        sourcegraph=FakeDiscovery("sourcegraph"),
                        github_search=FakeDiscovery("github-code-search"),
                        metadata=FakeMetadata(),
                        scan_runner=runner,
                        citation_pipeline=FakeCitationPipeline(),
                    )
                    with self.assertRaisesRegex(
                        PipelineError,
                        "exactly cover|more than once",
                    ):
                        pipeline.run(
                            mode="onboard",
                            library_ids=("cublas",),
                            budgets=self.budgets(),
                        )
                    self.assertEqual(
                        prior, (live / "manifest.json").read_bytes()
                    )

    def test_scan_failure_persists_typed_diagnostics_and_bounded_retry(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=typed_error_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            with self.assertRaisesRegex(
                PipelineError, "selected scans unresolved"
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=self.budgets(),
                )
            with StateDB(root / ".state/collector.sqlite3") as state:
                task = state.connection.execute(
                    """
                    SELECT status, attempts, max_attempts, error_code,
                           result_json
                    FROM tasks
                    WHERE stage='scan'
                    ORDER BY task_id DESC
                    LIMIT 1
                    """
                ).fetchone()
                result = json.loads(task["result_json"])
        self.assertEqual("failed", task["status"])
        self.assertEqual(2, task["attempts"])
        self.assertEqual(2, task["max_attempts"])
        self.assertEqual("repository_timeout", task["error_code"])
        self.assertEqual("scan-failure", result["kind"])
        self.assertTrue(result["retryable"])
        self.assertEqual(
            "repository wall deadline exhausted", result["error"]
        )
        self.assertEqual(7, result["git_subprocess_count"])
        self.assertEqual(2, result["network_fetch_count"])

    def test_resume_reports_terminal_scan_failure_without_redispatch(self):
        calls = []

        def recording_runner(*args, **kwargs):
            calls.append(tuple(task.full_name for task in args[0]))
            return typed_error_scan_runner(*args, **kwargs)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=recording_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            for _attempt in range(2):
                with self.assertRaisesRegex(
                    PipelineError, "1 selected scans unresolved"
                ):
                    pipeline.run(
                        mode="onboard",
                        library_ids=("cublas",),
                        budgets=self.budgets(),
                    )
            with StateDB(root / ".state/collector.sqlite3") as state:
                task = state.connection.execute(
                    """
                    SELECT status,attempts,max_attempts,error_code
                    FROM tasks WHERE stage='scan'
                    ORDER BY task_id DESC LIMIT 1
                    """
                ).fetchone()

        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call == ("public/example",) for call in calls))
        self.assertEqual(task["status"], "failed")
        self.assertEqual(task["attempts"], 2)
        self.assertEqual(task["max_attempts"], 2)
        self.assertEqual(task["error_code"], "repository_timeout")

    def test_resume_dispatches_pending_but_not_terminal_scan_tasks(self):
        class TwoRepoDiscovery(FakeDiscovery):
            def search(self, **kwargs):
                result = super().search(**kwargs)
                first = result.observations[0]
                second = dataclasses.replace(
                    first,
                    repo_full_name="public/legacy-a",
                    repo_node_id=(
                        "R_legacy_a"
                        if self.source == "github-code-search"
                        else None
                    ),
                    matched_path="src/legacy.cu",
                )
                partition = dataclasses.replace(
                    result.certificate.partitions[0],
                    total_count=2,
                    fetched_count=2,
                )
                certificate = dataclasses.replace(
                    result.certificate,
                    observations_count=2,
                    partitions=(partition,),
                )
                return DiscoveryResult(
                    (first, second), (), certificate
                )

        def fail_first_then_stop(
            tasks, _libraries, _cache_root, on_result, **kwargs
        ):
            first = tasks[0]
            kwargs["before_task"](first)
            outcome = ScanOutcome(
                full_name=first.full_name,
                head_sha=first.head_sha,
                status="error",
                result=None,
                seconds=0.01,
                candidate_library_ids=first.candidate_library_ids,
                error_code="detector_error",
                error_retryable=False,
                error="fixture terminal detector failure",
            )
            on_result(outcome)
            raise PipelineError("fixture coordinator stop")

        resumed_batches = []

        def resumed_runner(*args, **kwargs):
            resumed_batches.append(
                tuple(task.full_name for task in args[0])
            )
            return fake_scan_runner(*args, **kwargs)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=TwoRepoDiscovery("sourcegraph"),
                github_search=TwoRepoDiscovery("github-code-search"),
                metadata=CrashNearEndMetadata(crash_key=None),
                scan_runner=fail_first_then_stop,
                citation_pipeline=FakeCitationPipeline(),
            )
            with self.assertRaisesRegex(
                PipelineError, "fixture coordinator stop"
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=self.budgets(),
                )
            pipeline.scan_runner = resumed_runner
            with self.assertRaisesRegex(
                PipelineError, "1 selected scans unresolved"
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=self.budgets(),
                )
            with StateDB(root / ".state/collector.sqlite3") as state:
                tasks = state.connection.execute(
                    """
                    SELECT repositories.full_name,tasks.status,tasks.attempts,
                           tasks.error_code
                    FROM tasks JOIN repositories
                      ON repositories.node_id=tasks.repository_id
                    WHERE tasks.stage='scan'
                    ORDER BY lower(repositories.full_name)
                    """
                ).fetchall()

        self.assertEqual(resumed_batches, [("public/legacy-a",)])
        self.assertEqual(
            [tuple(row) for row in tasks],
            [
                ("public/example", "failed", 1, "detector_error"),
                ("public/legacy-a", "complete", 1, None),
            ],
        )

    def test_phase8_retry_lane_does_not_reduce_normal_scan_workers(self):
        workers_seen = []

        def recording_runner(*args, **kwargs):
            workers_seen.append(kwargs["workers"])
            return typed_error_scan_runner(*args, **kwargs)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=recording_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            with self.assertRaisesRegex(
                PipelineError, "selected scans unresolved"
            ):
                pipeline.run(
                    mode="reconcile",
                    confirm_full=True,
                    library_ids=("cublas",),
                    budgets=RunBudgets.reconcile(),
                    reviewed_execution_contract=self.cohort_contract(
                        "cublas", metadata_batch_size=50
                    ),
                )
        self.assertEqual([14, 2], workers_seen)

    def test_scan_error_contract_distinguishes_retryable_and_detector_failures(self):
        self.assertEqual(
            (
                "invalid_notebook",
                False,
                "tracked notebook is invalid JSON; scan is incomplete",
            ),
            _scan_error_contract(
                "tracked notebook is invalid JSON; scan is incomplete"
            ),
        )
        code, retryable, detail = _scan_error_contract(
            "repository wall deadline exhausted at /Users/example/cache/repo"
        )
        self.assertEqual("repository_timeout", code)
        self.assertTrue(retryable)
        self.assertNotIn("/Users/", detail)
        self.assertEqual(
            ("detector_error", False),
            _scan_error_contract("unexpected detector invariant")[:2],
        )
        self.assertEqual(
            ("repository_git_timeout", True),
            _scan_error_contract(
                "git diff-tree --root -r timed out after 120.0s"
            )[:2],
        )
        self.assertEqual(
            (
                "repository_cache_integrity",
                True,
                "current-tree object is unavailable after hydration",
            ),
            _phase8_runtime_issue_contract(
                "detector_error",
                False,
                "current-tree object is unavailable after hydration",
            ),
        )
        self.assertEqual(
            ("detector_error", False, "unrelated detector invariant"),
            _phase8_runtime_issue_contract(
                "detector_error", False, "unrelated detector invariant"
            ),
        )
        self.assertEqual(
            (
                "repository_timeout",
                True,
                "repository scan exceeded 600s wall-clock cap",
            ),
            _phase8_runtime_issue_contract(
                "detector_error",
                False,
                "repository scan exceeded 600s wall-clock cap",
            ),
        )
        self.assertEqual(
            (
                "repository_cache_integrity",
                True,
                "detector-relevant sparse path is unavailable: src/CMakeLists.txt",
            ),
            _phase8_runtime_issue_contract(
                "detector_error",
                False,
                "detector-relevant sparse path is unavailable: src/CMakeLists.txt",
            ),
        )
        self.assertEqual(
            (
                "repository_content_unavailable",
                False,
                "public Git LFS object count exceeds the evidence budget",
            ),
            _phase8_runtime_issue_contract(
                "detector_error",
                False,
                "public Git LFS object count exceeds the evidence budget",
            ),
        )
        not_our_ref = (
            "git --git-dir [local-path] -c core.commitGraph=false: fatal: "
            "remote error: upload-pack: not our ref " + "a" * 40
        )
        self.assertEqual(
            ("repository_cache_integrity", True, not_our_ref),
            _phase8_runtime_issue_contract(
                "detector_error", False, not_our_ref
            ),
        )
        self.assertEqual(
            ("repository_git_timeout", True),
            _scan_error_contract(
                "git failed: git cat-file --batch timed out during bare triage"
            )[:2],
        )
        self.assertEqual(
            ("detector_error", False),
            _scan_error_contract(
                "detector inference timed out after 120.0s"
            )[:2],
        )
        self.assertEqual(
            ("repository_content_unavailable", False),
            _scan_error_contract(
                "tracked detector-relevant Git LFS object is unavailable"
            )[:2],
        )
        self.assertEqual(
            ("repository_content_unavailable", False),
            _scan_error_contract(
                "Smudge error: this repository exceeded its LFS budget"
            )[:2],
        )

    def test_excluded_repositories_never_reach_scanner_or_publication(self):
        cases = (
            ("HITS-MCM/gromacs-ramd", "cufftmp"),
            ("deepseek-ai/DeepEP", "nvshmem"),
            ("4shen/webshell", "cudss"),
        )
        for full_name, library_id in cases:
            with self.subTest(full_name=full_name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                calls = []

                def refusing_scan_runner(tasks, *_args, **_kwargs):
                    calls.extend(tasks)
                    return []

                pipeline = CollectorPipeline(
                    repo_root=root,
                    sourcegraph=FakeDiscovery("sourcegraph", full_name),
                    github_search=FakeDiscovery(
                        "github-code-search", full_name
                    ),
                    metadata=FakeMetadata(full_name),
                    scan_runner=refusing_scan_runner,
                    citation_pipeline=FakeCitationPipeline(),
                )
                result = pipeline.run(
                    mode="onboard",
                    library_ids=(library_id,),
                    budgets=self.budgets(),
                )
                self.assertEqual([], calls)
                self.assertEqual(0, result["scanned"])
                card = next(
                    item
                    for item in result["manifest"]["libraries"]
                    if item["id"] == library_id
                )
                self.assertEqual(0, card["confirmed_count"])
                self.assertEqual(
                    [], validate_v2(root / "data/v2")
                )
                with StateDB(root / ".state/collector.sqlite3") as state:
                    active = state.connection.execute(
                        """
                        SELECT COUNT(*) FROM candidates
                        WHERE library_id=? AND state='active'
                        """,
                        (library_id,),
                    ).fetchone()[0]
                    self.assertEqual(0, active)
                    repository = state.connection.execute(
                        "SELECT * FROM repositories WHERE full_name=?",
                        (full_name,),
                    ).fetchone()
                    if full_name.casefold() == "hits-mcm/gromacs-ramd":
                        self.assertIsNone(repository)
                    else:
                        self.assertIsNotNone(repository)

    def test_discovery_collision_exclusion_is_exact_and_future_safe(self):
        library = next(
            item for item in LIBRARIES if item["id"] == "cutensor"
        )
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
            matched_blob=(
                "d9e1feb37ad1930e04e092c3dff19949c8cd684c"
            ),
            partition="fixture",
        )
        self.assertTrue(
            _discovery_observation_excluded(observation, library)
        )
        for change in (
            {"matched_blob": "b" * 40},
            {"matched_path": "src/real_cutensor.cu"},
            {"signal_id": "header-00"},
            {"repo_full_name": "aarnphm/renamed"},
        ):
            with self.subTest(change=change):
                candidate = dataclasses.replace(
                    observation, **change
                )
                self.assertFalse(
                    _discovery_observation_excluded(
                        candidate, library
                    )
                )

    def test_exact_discovery_collision_never_reaches_scanner(self):
        github = FakeDiscovery(
            "github-code-search",
            "aarnphm/aarnphm.github.io",
        )
        original_github_search = github.search

        def exact_github_search(**kwargs):
            result = original_github_search(**kwargs)
            if kwargs["signal_id"] != "broad-00":
                return dataclasses.replace(
                    result,
                    observations=(),
                    certificate=dataclasses.replace(
                        result.certificate,
                        observations_count=0,
                    ),
                )
            observation = dataclasses.replace(
                result.observations[0],
                matched_path="content/lectures/420/index.md",
                matched_blob=(
                    "d9e1feb37ad1930e04e092c3dff19949c8cd684c"
                ),
            )
            return dataclasses.replace(
                result,
                observations=(observation,),
                certificate=dataclasses.replace(
                    result.certificate,
                    observations_count=1,
                ),
            )

        github.search = exact_github_search
        sourcegraph = FakeDiscovery(
            "sourcegraph",
            "aarnphm/aarnphm.github.io",
        )
        original_sourcegraph_search = sourcegraph.search

        def empty_sourcegraph_search(**kwargs):
            result = original_sourcegraph_search(**kwargs)
            return dataclasses.replace(
                result,
                observations=(),
                certificate=dataclasses.replace(
                    result.certificate,
                    observations_count=0,
                ),
            )

        sourcegraph.search = empty_sourcegraph_search
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            calls = []

            def refusing_scan_runner(tasks, *_args, **_kwargs):
                calls.extend(tasks)
                return []

            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=sourcegraph,
                github_search=github,
                metadata=FakeMetadata(
                    "aarnphm/aarnphm.github.io"
                ),
                scan_runner=refusing_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            result = pipeline.run(
                mode="onboard",
                library_ids=("cutensor",),
                budgets=self.budgets(),
            )
            self.assertEqual([], calls)
            self.assertEqual(0, result["scanned"])
            with StateDB(root / ".state/collector.sqlite3") as state:
                self.assertEqual(
                    0,
                    state.connection.execute(
                        """
                        SELECT COUNT(*) FROM candidates
                        WHERE library_id='cutensor' AND state='active'
                        """
                    ).fetchone()[0],
                )

    def test_global_exclusion_purges_prior_checkpoint_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            pipeline = CollectorPipeline(
                repo_root=root,
                metadata=FakeMetadata("HITS-MCM/gromacs-ramd"),
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                library = next(
                    item for item in LIBRARIES if item["id"] == "cufftmp"
                )
                plan = build_plan(
                    mode="refresh",
                    state_path=state.path,
                    data_dir=root / "data",
                    libraries=[library],
                )
                values = plan.fingerprints.libraries["cufftmp"]
                state.upsert_library(
                    "cufftmp",
                    catalog=library,
                    fingerprints={
                        **values.as_dict(),
                        "dating": plan.fingerprints.dating,
                        "aggregation": plan.fingerprints.aggregation,
                    },
                )
                state.upsert_repository({
                    "node_id": "R_public_example",
                    "full_name": "HITS-MCM/gromacs-ramd",
                    "visibility": "PUBLIC",
                    "head_sha": "a" * 40,
                    "metadata": {"visibility": "PUBLIC"},
                })
                state.add_candidate(
                    repository_id="R_public_example",
                    library_id="cufftmp",
                    source="legacy-release",
                    query_fp="last-good-v1",
                    coverage_epoch="prior",
                )
                pipeline._resolve_metadata(
                    state,
                    (),
                    {},
                    (("R_public_example", "HITS-MCM/gromacs-ramd"),),
                )
                self.assertEqual(
                    0,
                    state.connection.execute(
                        "SELECT COUNT(*) FROM repositories"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0,
                    state.connection.execute(
                        "SELECT COUNT(*) FROM candidates"
                    ).fetchone()[0],
                )

    def test_nvpl_vendor_lineage_is_separate_and_retires_active_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            libraries = [
                next(item for item in LIBRARIES if item["id"] == library_id)
                for library_id in ("nvpl", "cublas")
            ]
            pipeline = CollectorPipeline(
                repo_root=root,
                metadata=FakeMetadata("community/accelerator"),
            )
            plan = build_plan(
                mode="refresh",
                state_path=root / ".state/collector.sqlite3",
                data_dir=root / "data",
                libraries=libraries,
            )
            pipeline._active_plan = plan
            repository_id = "R_public_example"
            full_name = "community/accelerator"
            evidence = {
                "classification": "confirmed",
                "language": "C++",
                "first_integration": "2026-07-01",
                "first_integration_commit": "b" * 12,
                "own_source_files": ["src/example.cpp"],
                "own_source_file_count": 1,
                "vendored_present": False,
                "ai_on_integration_commit": False,
                "ai_on_integration_agents": [],
                "operators": [],
            }
            with StateDB(root / ".state/collector.sqlite3") as state:
                for library in libraries:
                    values = plan.fingerprints.libraries[library["id"]]
                    state.upsert_library(
                        library["id"],
                        catalog=library,
                        fingerprints={
                            **values.as_dict(),
                            "dating": plan.fingerprints.dating,
                            "aggregation": plan.fingerprints.aggregation,
                        },
                    )
                state.upsert_repository({
                    "node_id": repository_id,
                    "full_name": full_name,
                    "visibility": "PUBLIC",
                    "head_sha": "a" * 40,
                    "metadata": {
                        "visibility": "PUBLIC",
                        "source": {
                            "nameWithOwner": "ggml-org/llama.cpp",
                        },
                    },
                })
                for library in libraries:
                    state.add_candidate(
                        repository_id=repository_id,
                        library_id=library["id"],
                        source="sourcegraph",
                        query_fp="prior-" + library["id"],
                        coverage_epoch="prior",
                    )
                    state.record_scan_result(
                        repository_id=repository_id,
                        library_id=library["id"],
                        head_sha="a" * 40,
                        detector_fp=plan.fingerprints.libraries[
                            library["id"]
                        ].detector,
                        classification="confirmed",
                        status="clean",
                        evidence=evidence,
                    )

                (
                    _resolution,
                    publishable,
                    by_requested_name,
                    by_node,
                ) = pipeline._resolve_metadata(
                    state,
                    (),
                    {},
                    ((repository_id, full_name),),
                )
                persisted_metadata = json.loads(
                    state.get_repository(repository_id)["metadata_json"]
                )
                self.assertEqual(
                    "ggml-org/llama.cpp",
                    persisted_metadata["source"]["nameWithOwner"],
                )
                grouped = pipeline._persist_candidates(
                    state,
                    "filter-run",
                    (),
                    {},
                    {
                        full_name: {"nvpl", "cublas"},
                    },
                    publishable,
                    by_requested_name,
                    by_node,
                )
                self.assertEqual(
                    {full_name: {"cublas"}},
                    grouped,
                )
                candidate_states = {
                    row["library_id"]: row["state"]
                    for row in state.connection.execute(
                        """
                        SELECT library_id, state FROM candidates
                        WHERE repository_id=?
                        """,
                        (repository_id,),
                    )
                }
                self.assertEqual("rejected", candidate_states["nvpl"])
                self.assertEqual("active", candidate_states["cublas"])

                current, _timeseries = pipeline._materialize(
                    state,
                    libraries,
                    {"certificates": []},
                    mode="refresh",
                    selected_library_ids={"nvpl", "cublas"},
                    scan_quality={},
                )
                repository = next(
                    repo
                    for repo in current["repos"]
                    if repo["full_name"] == full_name
                )
                self.assertEqual(
                    ["cublas"],
                    [entry["library_id"] for entry in repository["libraries"]],
                )
                self.assertEqual(
                    "rejected",
                    state.connection.execute(
                        """
                        SELECT state FROM candidates
                        WHERE repository_id=? AND library_id='nvpl'
                        """,
                        (repository_id,),
                    ).fetchone()["state"],
                )

    def test_exact_repository_exceptions_do_not_reopen_vendor_copies(self):
        nvpl = next(item for item in LIBRARIES if item["id"] == "nvpl")
        nvshmem = next(item for item in LIBRARIES if item["id"] == "nvshmem")
        for name, library in (
            ("pytorch/pytorch", nvpl),
            ("lattice/quda", nvshmem),
            ("bytedance/flux", nvshmem),
            ("ROCm/TransformerEngine", nvshmem),
        ):
            with self.subTest(name=name):
                self.assertFalse(_library_repository_excluded(name, library))
        self.assertTrue(
            _library_repository_excluded(
                "community/pytorch-copy",
                nvpl,
                {"parent": "pytorch/pytorch"},
            )
        )
        self.assertTrue(
            _library_repository_excluded(
                "community/transformer_engine-copy", nvshmem
            )
        )

    def test_nvpl_component_bucket_override_is_exact_head_and_path(self):
        evidence = {
            "_first_use_boundaries": {
                "primary": {"evidence_path": "Dockerfile"}
            }
        }
        self.assertEqual(
            ("BLAS", "LAPACK"),
            reviewed_components(
                "amarrmb/jetson-assistant",
                "721506a4e915268f3caf18513b42854a85f84241",
                evidence,
            ),
        )
        self.assertEqual(
            (),
            reviewed_components(
                "amarrmb/jetson-assistant", "0" * 40, evidence
            ),
        )

    def test_v1_nvpl_subtypes_are_exact_without_changing_v2_band(self):
        repositories = [{
            "full_name": "public/example",
            "libraries": [{
                "library_id": "nvpl",
                "classification": "bundled",
                "operators": ["FFT"],
            }],
        }]
        legacy = {
            "repos": [{
                "full_name": "public/example",
                "libraries": [{
                    "library_id": "nvpl",
                    "classification": "targeted",
                    "operators": ["BLAS", "LAPACK"],
                }],
            }]
        }
        _preserve_nvpl_component_memberships(
            repositories,
            legacy,
            {"public/example": "public/example"},
        )
        self.assertEqual(
            ["BLAS", "LAPACK"],
            repositories[0]["libraries"][0]["operators"],
        )
        self.assertEqual(
            "bundled",
            repositories[0]["libraries"][0]["classification"],
        )

    def test_empty_v1_nvpl_subtypes_clear_new_v2_subtypes_only(self):
        repositories = [{
            "full_name": "public/example",
            "libraries": [{
                "library_id": "nvpl",
                "classification": "targeted",
                "operators": ["FFT"],
            }],
        }]
        legacy = {
            "repos": [{
                "full_name": "public/example",
                "libraries": [{
                    "library_id": "nvpl",
                    "classification": "bundled",
                    "operators": [],
                }],
            }]
        }
        _preserve_nvpl_component_memberships(
            repositories,
            legacy,
            {"public/example": "public/example"},
        )
        self.assertEqual([], repositories[0]["libraries"][0]["operators"])
        self.assertEqual(
            "targeted",
            repositories[0]["libraries"][0]["classification"],
        )

    def test_nvpl_vendor_lineage_is_not_carried_from_v1(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = root / "data"
            data.mkdir()
            name = "community/accelerator"
            (data / "current.json").write_text(json.dumps({
                "libraries": [
                    {"id": "nvpl"},
                    {"id": "cublas"},
                ],
                "repos": [{
                    "full_name": name,
                    "libraries": [
                        {"library_id": "nvpl"},
                        {"library_id": "cublas"},
                    ],
                }],
            }))
            repositories, _carried, _legacy = (
                _carry_forward_unselected_v1(
                    [],
                    data,
                    set(),
                    {name.casefold(): name},
                    {
                        name.casefold(): {
                            "source": "ggml-org/llama.cpp",
                        },
                    },
                )
            )
            self.assertEqual(1, len(repositories))
            self.assertEqual(
                ["cublas"],
                [
                    entry["library_id"]
                    for entry in repositories[0]["libraries"]
                ],
            )

    def test_candidate_identity_reconciles_legacy_node_id_by_public_name(self):
        legacy_node_id = "MDEwOlJlcG9zaXRvcnkxMjM0NTY="
        canonical_node_id = "R_kgDOcanonical"
        item = RepositoryMetadata(
            request_key="name:public/example",
            requested_node_id=None,
            requested_full_name="public/example",
            node_id=canonical_node_id,
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
        observation = DiscoveryObservation(
            repo_full_name="public/example",
            repo_node_id=legacy_node_id,
            library_id="cublas",
            signal_id="header",
            source="github-code-search",
            query_fingerprint="query-fp",
            observed_at=NOW,
            visibility="PUBLIC",
        )
        with tempfile.TemporaryDirectory() as td:
            pipeline = CollectorPipeline(repo_root=td)
            with StateDB(Path(td) / "state.sqlite3") as state:
                state.upsert_library(
                    "cublas",
                    catalog={"name": "cuBLAS"},
                    fingerprints={
                        "discovery": "a" * 64,
                        "detector": "b" * 64,
                        "citation": "c" * 64,
                        "dating": "d" * 64,
                        "aggregation": "e" * 64,
                        "presentation": "f" * 64,
                        "release": "1" * 64,
                    },
                )
                state.upsert_repository({
                    "node_id": canonical_node_id,
                    "full_name": "public/example",
                    "visibility": "PUBLIC",
                    "head_sha": "a" * 40,
                })
                grouped = pipeline._persist_candidates(
                    state,
                    "identity-run",
                    (observation,),
                    {},
                    {},
                    {"public/example": item},
                    {"public/example": item},
                    {canonical_node_id: item},
                )
                candidate = state.connection.execute(
                    """
                    SELECT repository_id, library_id
                    FROM candidates
                    """
                ).fetchone()
        self.assertEqual({"public/example": {"cublas"}}, grouped)
        self.assertEqual(canonical_node_id, candidate["repository_id"])
        self.assertEqual("cublas", candidate["library_id"])
        self.assertEqual(
            1,
            pipeline._candidate_identity_metrics[
                "name_fallback_after_node_miss"
            ],
        )

    def test_candidate_identity_reconciles_rename_to_canonical_repository(self):
        item = RepositoryMetadata(
            request_key="name:public/old-name",
            requested_node_id=None,
            requested_full_name="public/old-name",
            node_id="R_kgDOrenamed",
            full_name="public/new-name",
            visibility="PUBLIC",
            is_private=False,
            is_fork=False,
            is_archived=False,
            default_branch="main",
            head_oid="a" * 40,
            renamed=True,
            status="ok",
        )
        observation = DiscoveryObservation(
            repo_full_name="public/old-name",
            repo_node_id="MDEwOlJlcG9zaXRvcnk5OTk=",
            library_id="cublas",
            signal_id="header",
            source="github-code-search",
            query_fingerprint="query-fp",
            observed_at=NOW,
            visibility="PUBLIC",
        )
        with tempfile.TemporaryDirectory() as td:
            pipeline = CollectorPipeline(repo_root=td)
            with StateDB(Path(td) / "state.sqlite3") as state:
                state.upsert_library(
                    "cublas",
                    catalog={"name": "cuBLAS"},
                    fingerprints={
                        "discovery": "a" * 64,
                        "detector": "b" * 64,
                        "citation": "c" * 64,
                        "dating": "d" * 64,
                        "aggregation": "e" * 64,
                        "presentation": "f" * 64,
                        "release": "1" * 64,
                    },
                )
                state.upsert_repository({
                    "node_id": item.node_id,
                    "full_name": item.full_name,
                    "visibility": "PUBLIC",
                    "head_sha": "a" * 40,
                })
                grouped = pipeline._persist_candidates(
                    state,
                    "rename-run",
                    (observation,),
                    {},
                    {},
                    {item.full_name: item},
                    {item.requested_full_name.casefold(): item},
                    {item.node_id: item},
                )
        self.assertEqual({"public/new-name": {"cublas"}}, grouped)

    def test_candidate_identity_collision_and_nonpublic_results_fail_closed(self):
        def metadata(node_id, full_name, *, requested_name=None, fork=False):
            return RepositoryMetadata(
                request_key="name:" + (requested_name or full_name),
                requested_node_id=None,
                requested_full_name=requested_name or full_name,
                node_id=node_id,
                full_name=full_name,
                visibility="PUBLIC",
                is_private=False,
                is_fork=fork,
                is_archived=False,
                default_branch="main",
                head_oid="a" * 40,
                renamed=(requested_name or full_name) != full_name,
                status="ok",
            )

        item_a = metadata("R_a", "public/a")
        item_b = metadata("R_b", "public/b")
        collision = DiscoveryObservation(
            repo_full_name="public/b",
            repo_node_id="R_a",
            library_id="cublas",
            signal_id="header",
            source="github-code-search",
            query_fingerprint="query-fp",
            observed_at=NOW,
            visibility="PUBLIC",
        )
        fork = metadata("R_fork", "public/fork", fork=True)
        fork_observation = dataclasses.replace(
            collision,
            repo_full_name="public/fork",
            repo_node_id="R_fork",
        )
        alias_a = metadata(
            "R_alias_a", "public/alias-a", requested_name="public/old"
        )
        alias_b = metadata(
            "R_alias_b", "public/alias-b", requested_name="public/old"
        )
        with tempfile.TemporaryDirectory() as td:
            pipeline = CollectorPipeline(repo_root=td)
            with StateDB(Path(td) / "state.sqlite3") as state:
                with self.assertRaisesRegex(
                    PipelineError, "node/name identity collision"
                ):
                    pipeline._persist_candidates(
                        state,
                        "collision-run",
                        (collision,),
                        {},
                        {},
                        {"public/a": item_a, "public/b": item_b},
                        {
                            "public/a": item_a,
                            "public/b": item_b,
                        },
                        {"R_a": item_a, "R_b": item_b},
                    )
                with self.assertRaisesRegex(
                    PipelineError, "requested-name collision"
                ):
                    pipeline._persist_candidates(
                        state,
                        "alias-collision-run",
                        (),
                        {},
                        {},
                        {
                            "public/alias-a": alias_a,
                            "public/alias-b": alias_b,
                        },
                        {},
                        {
                            "R_alias_a": alias_a,
                            "R_alias_b": alias_b,
                        },
                    )
                grouped = pipeline._persist_candidates(
                    state,
                    "fork-run",
                    (fork_observation,),
                    {},
                    {},
                    {},
                    {"public/fork": fork},
                    {"R_fork": fork},
                )
        self.assertEqual({}, grouped)

    def test_cold_targeted_onboard_carries_only_current_public_renamed_v1_history(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = root / "data"
            data.mkdir()
            legacy_timeseries = {
                "cufftdx": {
                    "released_on": "2023-01",
                    "released_confidence": "high",
                    "points": [
                        {
                            "month": "2025-01",
                            "confirmed": 1,
                            "bundled": 0,
                            "targeted": 0,
                            "cumulative_ai": 0,
                        }
                    ],
                }
            }
            legacy_current = {
                "generated_at": "2026-07-15T00:00:00Z",
                "libraries": [
                    {
                        "id": "cublas",
                        "name": "cuBLAS",
                        "confirmed_count": 1,
                    },
                    {
                        "id": "cufftdx",
                        "name": "cuFFTDx",
                        "confirmed_count": 1,
                        "bundled_count": 0,
                        "targeted_count": 0,
                        "headline_count": 1,
                        "sparkline": [1],
                        "sparkline_months": ["2025-01"],
                    },
                ],
                "repos": [
                    {
                        "full_name": "public/example",
                        "html_url": "https://github.com/public/example",
                        "owner": "public",
                        "stars": 4,
                        "forks": 0,
                        "ai_assisted": False,
                        "libraries": [{
                            "library_id": "cublas",
                            "classification": "confirmed",
                            "first_integration": "2020-01-01",
                            "first_integration_commit": "old-cublas",
                            "own_source_files": ["old.cu"],
                            "operators": [],
                        }],
                    },
                    {
                        "full_name": "public/legacy",
                        "html_url": "https://github.com/public/legacy",
                        "owner": "public",
                        "stars": 3,
                        "forks": 0,
                        "ai_assisted": False,
                        "libraries": [{
                            "library_id": "cufftdx",
                            "classification": "confirmed",
                            "first_integration": "2025-01-02",
                            "first_integration_commit": "legacy-dx",
                            "own_source_files": ["dx.cu"],
                            "operators": [],
                        }],
                    },
                ],
                "discovery_stats": {
                    "cufftdx": {
                        "coverage_gaps": [],
                        "sources": {"legacy": {"repos": 1}},
                    }
                },
            }
            (data / "current.json").write_text(
                json.dumps(legacy_current)
            )
            (data / "timeseries.json").write_text(
                json.dumps(legacy_timeseries)
            )
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            pipeline.run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self.budgets(),
            )
            manifest = json.loads(
                (data / "v2/manifest.json").read_text()
            )
            cufftdx = next(
                card for card in manifest["libraries"]
                if card["id"] == "cufftdx"
            )
            self.assertEqual(cufftdx["confirmed_count"], 1)
            cufftdx_index = json.loads(
                (data / "v2" / cufftdx["index"]["path"]).read_text()
            )
            cufftdx_rows = []
            for descriptor in cufftdx_index["repo_parts"]:
                cufftdx_rows.extend(
                    json.loads(
                        (data / "v2" / descriptor["path"]).read_text()
                    )["rows"]
                )
            self.assertEqual(
                [row["full_name"] for row in cufftdx_rows],
                ["public/example"],
            )
            self.assertEqual(
                cufftdx_index["timeseries"], legacy_timeseries["cufftdx"]
            )

            cublas = next(
                card for card in manifest["libraries"]
                if card["id"] == "cublas"
            )
            cublas_index = json.loads(
                (data / "v2" / cublas["index"]["path"]).read_text()
            )
            cublas_row = json.loads(
                (
                    data
                    / "v2"
                    / cublas_index["repo_parts"][0]["path"]
                ).read_text()
            )["rows"][0]
            self.assertEqual(
                cublas_row["libraries"][0]["first_integration"],
                "2026-07-01",
            )
            quality = json.loads(
                (data / "v2" / manifest["quality"]["path"]).read_text()
            )
            self.assertTrue(quality["migration"]["mixed_v1_v2"])
            self.assertTrue(quality["migration"]["stale"])
            self.assertIn(
                "cufftdx",
                quality["migration"]["carried_forward_library_ids"],
            )
            self.assertEqual(
                quality["discovery_stats"]["cufftdx"]["evidence_kind"],
                "carried-forward-v1",
            )

    def test_phase8_cohort_is_current_only_for_selected_and_stale_for_v1_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = root / "data"
            data.mkdir()
            (data / "current.json").write_text(json.dumps({
                "generated_at": "2026-07-15T00:00:00Z",
                "libraries": [{
                    "id": "cufftdx",
                    "name": "cuFFTDx",
                    "confirmed_count": 1,
                    "bundled_count": 0,
                    "targeted_count": 0,
                    "headline_count": 1,
                }],
                "repos": [{
                    "full_name": "public/legacy-a",
                    "html_url": "https://github.com/public/legacy-a",
                    "owner": "public",
                    "stars": 1,
                    "forks": 0,
                    "ai_assisted": False,
                    "libraries": [{
                        "library_id": "cufftdx",
                        "classification": "confirmed",
                        "language": "CUDA",
                        "first_integration": "2025-01-02",
                        "first_integration_commit": "legacy-dx",
                        "own_source_files": ["dx.cu"],
                        "own_source_file_count": 1,
                        "operators": [],
                    }],
                }],
                "discovery_stats": {},
            }))
            legacy_timeseries = {
                "cufftdx": {
                    "released_on": "2023-01",
                    "released_confidence": "high",
                    "points": [{
                        "month": "2025-01",
                        "confirmed": 1,
                        "bundled": 0,
                        "targeted": 0,
                        "cumulative_ai": 0,
                    }],
                }
            }
            (data / "timeseries.json").write_text(
                json.dumps(legacy_timeseries)
            )
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=CrashNearEndMetadata(crash_key="never"),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            result = pipeline.run(
                mode="reconcile",
                confirm_full=True,
                library_ids=("cublas",),
                budgets=RunBudgets.reconcile(),
                reviewed_execution_contract=self.cohort_contract(
                    "cublas",
                    metadata_batch_size=1,
                ),
            )
            manifest = result["manifest"]
            self.assertEqual(
                "partial-portfolio", manifest["release"]["scope"]
            )
            self.assertEqual(
                "phase8-cohort-a", manifest["release"]["run_class"]
            )
            self.assertEqual(
                ["cublas"],
                manifest["portfolio_coverage"]["selected_library_ids"],
            )
            cards = {card["id"]: card for card in manifest["libraries"]}
            self.assertEqual(
                "collected", cards["cublas"]["collection_status"]
            )
            for library_id in ("cufftdx", "warp"):
                card = cards[library_id]
                self.assertEqual(
                    "not_collected", card["collection_status"]
                )
                self.assertEqual(
                    {
                        "confirmed": "not_evaluated",
                        "bundled": "not_evaluated",
                        "targeted": "not_evaluated",
                    },
                    card["classification_coverage"],
                )
                self.assertIsNone(card["confirmed_count"])
                self.assertIsNone(card["bundled_count"])
                self.assertIsNone(card["targeted_count"])
                self.assertIsNone(card["headline_count"])

            cufftdx_index = json.loads(
                (
                    data
                    / "v2"
                    / cards["cufftdx"]["index"]["path"]
                ).read_text()
            )
            rows = []
            for descriptor in cufftdx_index["repo_parts"]:
                rows.extend(json.loads(
                    (data / "v2" / descriptor["path"]).read_text()
                )["rows"])
            carried = rows[0]["libraries"][0]
            self.assertTrue(carried["carried_forward"])
            self.assertTrue(carried["stale"])
            self.assertEqual(
                "2026-07-15T00:00:00Z", carried["as_of"]
            )
            self.assertEqual(0, cufftdx_index["current_row_count"])
            self.assertEqual(1, cufftdx_index["carried_forward_row_count"])
            self.assertEqual(
                legacy_timeseries["cufftdx"],
                cufftdx_index["timeseries"],
            )
            self.assertEqual(
                1, manifest["totals"]["confirmed_integrator_repos"]
            )
            quality = json.loads(
                (data / "v2" / manifest["quality"]["path"]).read_text()
            )
            self.assertEqual(
                "partial-cohort-reconcile",
                quality["scan"]["coverage_claim"],
            )
            self.assertEqual(
                "phase8-cohort-a", quality["scan"]["run_class"]
            )
            self.assertEqual(
                ["cublas"],
                quality["migration"]["selected_library_ids"],
            )
            self.assertIn(
                "cufftdx",
                quality["migration"]["carried_forward_library_ids"],
            )
            self.assertEqual(
                "phase8-cohort-a", result["report"]["run_class"]
            )
            self.assertEqual(
                "partial_cohort_reconciliation",
                result["report"]["slo"]["class"],
            )
            self.assertEqual([], validate_v2(data / "v2"))

    def test_reconcile_with_skipped_source_file_preserves_prior_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live = root / "data/v2"
            live.mkdir(parents=True)
            prior = b'{"release":{"id":"prior-release"}}\n'
            (live / "manifest.json").write_bytes(prior)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=skipped_large_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            with self.assertRaisesRegex(
                PipelineError, "skipped oversized own-source files"
            ):
                pipeline.run(
                    mode="reconcile",
                    confirm_full=True,
                    budgets=self.budgets(
                        sourcegraph_requests=2_000,
                        github_requests=2_000,
                        scans=10,
                    ),
                )
            self.assertEqual(prior, (live / "manifest.json").read_bytes())

    def test_reconcile_with_pruned_policy_asset_publishes_complete_quality(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=pruned_large_asset_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            result = pipeline.run(
                mode="reconcile",
                confirm_full=True,
                budgets=self.budgets(
                    sourcegraph_requests=2_000,
                    github_requests=2_000,
                    scans=10,
                ),
            )
            manifest = result["manifest"]
            quality = json.loads(
                (
                    root
                    / "data/v2"
                    / manifest["quality"]["path"]
                ).read_text()
            )
            self.assertEqual(quality["scan"]["skipped_large_files"], 0)
            self.assertEqual(quality["scan"]["pruned_large_assets"], 1)
            self.assertEqual(quality["scan"]["policy"], SCAN_POLICY)
            self.assertEqual(quality["scan"]["freshness"], SCAN_FRESHNESS)
            self.assertTrue(quality["scan"]["complete"])
            self.assertEqual([], validate_v2(root / "data/v2"))

            with StateDB(root / ".state/collector.sqlite3") as state:
                scan_stage = state.connection.execute(
                    """
                    SELECT metrics_json FROM stages
                    WHERE run_id=? AND stage='scan'
                    """,
                    (result["run_id"],),
                ).fetchone()
            self.assertIsNotNone(scan_stage)
            scan_metrics = json.loads(scan_stage["metrics_json"])
            self.assertEqual(scan_metrics["skipped_large_files"], 0)
            self.assertEqual(scan_metrics["pruned_large_assets"], 1)

    def test_git_materialization_budget_stops_during_scan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            budgets = dataclasses.replace(
                self.budgets(), max_git_materialized_bytes=100
            )
            with self.assertRaisesRegex(
                BudgetExceeded,
                "Git materialization byte budget exhausted during scan",
            ):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=budgets,
                )
            self.assertFalse(
                (root / "data/v2/manifest.json").exists()
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                attempt = state.connection.execute(
                    """
                    SELECT status, retryable, error_code, usage_complete,
                           network_materialized_bytes
                    FROM scan_attempts
                    """
                ).fetchone()
                task = state.connection.execute(
                    """
                    SELECT status, error_code
                    FROM tasks WHERE stage='scan'
                    """
                ).fetchone()
            self.assertIsNotNone(attempt)
            self.assertEqual("failed", attempt["status"])
            self.assertEqual(0, attempt["retryable"])
            self.assertEqual(
                "git_materialization_budget_exceeded",
                attempt["error_code"],
            )
            self.assertEqual(1, attempt["usage_complete"])
            self.assertEqual(
                123, attempt["network_materialized_bytes"]
            )
            self.assertEqual("failed", task["status"])
            self.assertEqual(
                "git_materialization_budget_exceeded",
                task["error_code"],
            )

    def test_late_checkpoint_overrun_never_installs_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            now = [0.0]
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
                clock=lambda: now[0],
            )
            original_export = StateDB.export_checkpoint_shards

            def export_then_expire(state, destination):
                result = original_export(state, destination)
                now[0] = 301.0
                return result

            with mock.patch.object(
                StateDB,
                "export_checkpoint_shards",
                new=export_then_expire,
            ):
                with self.assertRaisesRegex(
                    BudgetExceeded, "wall-time budget exceeded"
                ):
                    pipeline.run(
                        mode="onboard",
                        library_ids=("cublas",),
                        budgets=self.budgets(),
                    )
            self.assertFalse(
                (root / "data/v2/manifest.json").exists()
            )

    def test_checkpoint_failure_rolls_back_v2_and_rejects_release(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live = root / "data/v2"
            checkpoint = root / "data/state-checkpoint"
            live.mkdir(parents=True)
            checkpoint.mkdir(parents=True)
            prior_manifest = b'{"release":{"id":"prior-release"}}\n'
            prior_checkpoint = b'{"prior-checkpoint":true}\n'
            (live / "manifest.json").write_bytes(prior_manifest)
            (checkpoint / "manifest.json").write_bytes(prior_checkpoint)
            with StateDB(root / ".state/collector.sqlite3"):
                pass
            pipeline = CollectorPipeline(
                repo_root=root,
                sourcegraph=FakeDiscovery("sourcegraph"),
                github_search=FakeDiscovery("github-code-search"),
                metadata=FakeMetadata(),
                scan_runner=fake_scan_runner,
                citation_pipeline=FakeCitationPipeline(),
            )
            with mock.patch.object(
                StateDB,
                "export_checkpoint_shards",
                side_effect=OSError("synthetic checkpoint failure"),
            ):
                with self.assertRaisesRegex(
                    OSError, "synthetic checkpoint failure"
                ):
                    pipeline.run(
                        mode="onboard",
                        library_ids=("cublas",),
                        budgets=self.budgets(),
                    )
            self.assertEqual(
                prior_manifest, (live / "manifest.json").read_bytes()
            )
            self.assertEqual(
                prior_checkpoint, (checkpoint / "manifest.json").read_bytes()
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                release = state.connection.execute(
                    "SELECT status FROM releases ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                run = state.connection.execute(
                    "SELECT status FROM runs ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                self.assertEqual("rejected", release["status"])
                self.assertEqual("failed", run["status"])


class StateHardeningRegressionTests(unittest.TestCase):
    @staticmethod
    def fingerprints(char="a"):
        return {
            "discovery": char * 64,
            "detector": char * 64,
            "citation": char * 64,
            "dating": char * 64,
            "aggregation": char * 64,
            "presentation": char * 64,
            "release": char * 64,
        }

    @classmethod
    def seed_public_state(cls, state):
        state.upsert_library(
            "cublas",
            catalog={"name": "cuBLAS"},
            fingerprints=cls.fingerprints(),
        )
        state.upsert_repository({
            "node_id": "R_public",
            "full_name": "public/example",
            "visibility": "public",
            "head_sha": "a" * 40,
            "metadata": {"disk_usage_kb": 123},
        })

    def test_supersede_more_than_sixty_thousand_keys_without_sql_variables(self):
        with tempfile.TemporaryDirectory() as td:
            with StateDB(Path(td) / "state.sqlite3") as state:
                state.create_run(
                    "large-replan", mode="reconcile", status="running"
                )
                kept = state.enqueue_task(
                    "large-replan", "scan", "keep-this"
                )
                obsolete = state.enqueue_task(
                    "large-replan", "scan", "supersede-this"
                )
                keep_keys = ["keep-this"]
                keep_keys.extend(
                    f"not-enqueued-{ordinal}" for ordinal in range(60_001)
                )
                changed = state.supersede_tasks(
                    "large-replan",
                    "scan",
                    keep_task_keys=keep_keys,
                    reason="reviewed_replan",
                )
                self.assertEqual(1, changed)
                rows = {
                    row["task_id"]: dict(row)
                    for row in state.connection.execute(
                        "SELECT * FROM tasks ORDER BY task_id"
                    )
                }
                self.assertEqual("pending", rows[kept]["status"])
                self.assertEqual("complete", rows[obsolete]["status"])
                self.assertEqual(
                    {"reason": "reviewed_replan", "superseded": True},
                    json.loads(rows[obsolete]["result_json"]),
                )

    def test_reviewed_retry_reset_and_abandon_are_explicit_and_terminal(self):
        with tempfile.TemporaryDirectory() as td:
            with StateDB(Path(td) / "state.sqlite3") as state:
                state.create_run(
                    "interrupted", mode="refresh", status="running"
                )
                state.update_stage("interrupted", "discover", status="complete")
                state.update_stage("interrupted", "scan", status="running")
                state.update_stage("interrupted", "publish", status="pending")
                task_ids = {
                    name: state.enqueue_task("interrupted", "scan", name)
                    for name in ("pending", "failed", "running", "complete")
                }
                with state.transaction(immediate=True):
                    state.connection.execute(
                        """
                        UPDATE tasks SET status='failed', attempts=3,
                            error_code='exhausted', finished_at='old'
                        WHERE task_id=?
                        """,
                        (task_ids["failed"],),
                    )
                    state.connection.execute(
                        """
                        UPDATE tasks SET status='running', attempts=1,
                            lease_owner='dead-worker', lease_expires_at=1
                        WHERE task_id=?
                        """,
                        (task_ids["running"],),
                    )
                    state.connection.execute(
                        """
                        UPDATE tasks SET status='complete', result_json='{}',
                            finished_at='done'
                        WHERE task_id=?
                        """,
                        (task_ids["complete"],),
                    )
                state.finish_run("interrupted", status="failed")

                with self.assertRaisesRegex(ValueError, "machine-readable"):
                    state.reset_failed_tasks(
                        "interrupted", reason="not reviewed!"
                    )
                changed = state.reset_failed_tasks(
                    "interrupted", reason="operator_reviewed"
                )
                self.assertEqual(1, changed)
                reset = state.connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?",
                    (task_ids["failed"],),
                ).fetchone()
                self.assertEqual("pending", reset["status"])
                self.assertEqual(3, reset["attempts"])
                self.assertEqual(4, reset["max_attempts"])
                self.assertEqual(
                    "reviewed_retry:operator_reviewed",
                    reset["error_code"],
                )
                self.assertIsNone(reset["finished_at"])
                self.assertEqual(
                    "complete",
                    state.connection.execute(
                        "SELECT status FROM tasks WHERE task_id=?",
                        (task_ids["complete"],),
                    ).fetchone()[0],
                )
                self.assertEqual(
                    "running",
                    state.connection.execute(
                        "SELECT status FROM runs WHERE run_id='interrupted'"
                    ).fetchone()[0],
                )

                with self.assertRaisesRegex(ValueError, "machine-readable"):
                    state.abandon_run("interrupted", reason="not reviewed!")
                state.abandon_run(
                    "interrupted", reason="contract_superseded"
                )
                task_rows = {
                    row["task_key"]: dict(row)
                    for row in state.connection.execute(
                        "SELECT * FROM tasks WHERE run_id='interrupted'"
                    )
                }
                self.assertEqual("complete", task_rows["complete"]["status"])
                for key in ("pending", "failed", "running"):
                    self.assertEqual("failed", task_rows[key]["status"])
                    self.assertEqual(
                        "run_abandoned:contract_superseded",
                        task_rows[key]["error_code"],
                    )
                    self.assertIsNone(task_rows[key]["lease_owner"])
                stage_states = {
                    row["stage"]: row["status"]
                    for row in state.connection.execute(
                        "SELECT stage, status FROM stages WHERE run_id='interrupted'"
                    )
                }
                self.assertEqual(
                    {
                        "discover": "complete",
                        "scan": "failed",
                        "publish": "failed",
                    },
                    stage_states,
                )
                self.assertEqual(
                    "abandoned",
                    state.connection.execute(
                        "SELECT status FROM runs WHERE run_id='interrupted'"
                    ).fetchone()[0],
                )
                self.assertIsNone(
                    state.resume_compatible_run(mode="refresh")
                )
                with self.assertRaisesRegex(RuntimeError, "interrupted"):
                    state.reset_failed_tasks(
                        "interrupted", reason="too_late"
                    )

    def test_compaction_is_bounded_idempotent_and_retains_live_semantics(self):
        tick = {"value": 0}

        def now():
            tick["value"] += 1
            return "2026-07-27T00:%02d:%02dZ" % (
                tick["value"] // 60,
                tick["value"] % 60,
            )

        with tempfile.TemporaryDirectory() as td:
            with StateDB(Path(td) / "state.sqlite3", now=now) as state:
                self.seed_public_state(state)
                state.add_candidate(
                    repository_id="R_public",
                    library_id="cublas",
                    source="sourcegraph",
                    query_fp="active-query",
                    coverage_epoch="current",
                )
                state.record_scan_result(
                    repository_id="R_public",
                    library_id="cublas",
                    head_sha="a" * 40,
                    detector_fp="a" * 64,
                    classification="confirmed",
                    status="clean",
                )
                state.record_scan_result(
                    repository_id="R_public",
                    library_id="cublas",
                    head_sha="b" * 40,
                    detector_fp="b" * 64,
                    classification="rejected",
                    status="clean",
                )
                for ordinal in range(4):
                    state.record_repo_analysis(
                        repository_id="R_public",
                        head_sha="a" * 40,
                        ai_fp=f"ai-{ordinal}",
                        cff_fp=f"cff-{ordinal}",
                        analysis={"version": ordinal},
                        status="clean",
                    )
                state.record_repo_analysis(
                    repository_id="R_public",
                    head_sha="b" * 40,
                    ai_fp="old-ai",
                    cff_fp="old-cff",
                    analysis={"old": True},
                    status="clean",
                )
                for ordinal in range(4):
                    state.put_citation_cache(
                        library_id="cublas",
                        query_fp=f"query-{ordinal}",
                        work_id=f"work-{ordinal}",
                        payload_fp=f"payload-{ordinal}",
                        payload={"ordinal": ordinal},
                        sources={},
                        status="fresh",
                    )
                terminal_runs = []
                for ordinal in range(8):
                    run_id = f"terminal-{ordinal}"
                    terminal_runs.append(run_id)
                    state.create_run(
                        run_id, mode="refresh", status="running"
                    )
                    if ordinal % 3 == 0:
                        state.abandon_run(
                            run_id, reason="fixture_retention"
                        )
                    else:
                        state.finish_run(run_id, status="complete")
                state.create_run(
                    "still-running", mode="refresh", status="running"
                )
                state.create_run(
                    "still-failed", mode="refresh", status="running"
                )
                state.finish_run("still-failed", status="failed")
                for ordinal in range(6):
                    state.record_release(
                        f"release-{ordinal}",
                        run_id=terminal_runs[ordinal],
                        state_txn=f"txn-{ordinal}",
                        manifest_path="data/v2/manifest.json",
                        artifacts=[],
                        validation={"valid": ordinal % 2 == 0},
                        status=("published" if ordinal % 2 == 0 else "rejected"),
                    )
                state.record_release(
                    "release-staged",
                    run_id=terminal_runs[0],
                    state_txn="txn-staged",
                    manifest_path="data/v2/manifest.json",
                    artifacts=[],
                    validation={"valid": True},
                    status="staged",
                )

                deleted = state.compact_operational_history(
                    completed_runs=3,
                    releases=2,
                    citation_versions=2,
                    analysis_versions=2,
                )
                self.assertTrue(any(value > 0 for value in deleted.values()))
                retained_runs = {
                    row["run_id"]
                    for row in state.connection.execute(
                        "SELECT run_id FROM runs"
                    )
                }
                self.assertEqual(
                    {
                        "still-running",
                        "still-failed",
                        "terminal-5",
                        "terminal-6",
                        "terminal-7",
                    },
                    retained_runs,
                )
                self.assertEqual(
                    {"release-4", "release-5", "release-staged"},
                    {
                        row["release_id"]
                        for row in state.connection.execute(
                            "SELECT release_id FROM releases"
                        )
                    },
                )
                scan_rows = state.connection.execute(
                    """
                    SELECT head_sha, detector_fp FROM scan_results
                    ORDER BY scan_result_id
                    """
                ).fetchall()
                self.assertEqual(
                    [("a" * 40, "a" * 64)],
                    [(row["head_sha"], row["detector_fp"]) for row in scan_rows],
                )
                analyses = state.connection.execute(
                    """
                    SELECT head_sha, analysis_json FROM repo_analysis
                    ORDER BY analysis_id
                    """
                ).fetchall()
                self.assertEqual(2, len(analyses))
                self.assertTrue(
                    all(row["head_sha"] == "a" * 40 for row in analyses)
                )
                self.assertEqual(
                    {2, 3},
                    {
                        json.loads(row["analysis_json"])["version"]
                        for row in analyses
                    },
                )
                self.assertEqual(
                    {"query-2", "query-3"},
                    {
                        row["query_fp"]
                        for row in state.connection.execute(
                            "SELECT query_fp FROM citation_cache"
                        )
                    },
                )
                self.assertEqual(
                    1,
                    state.connection.execute(
                        "SELECT COUNT(*) FROM candidates WHERE state='active'"
                    ).fetchone()[0],
                )
                repeated = state.compact_operational_history(
                    completed_runs=3,
                    releases=2,
                    citation_versions=2,
                    analysis_versions=2,
                )
                self.assertTrue(repeated)
                self.assertTrue(
                    all(value == 0 for value in repeated.values()),
                    repeated,
                )

    def test_sharded_checkpoint_rejects_structural_and_size_corruption(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with StateDB(root / "source.sqlite3") as source:
                self.seed_public_state(source)
                for ordinal in range(2):
                    source.create_run(
                        f"run-{ordinal}",
                        mode="refresh",
                        status="running",
                    )
                    source.finish_run(
                        f"run-{ordinal}", status="complete"
                    )

                def exported(name):
                    destination = root / name
                    source.export_checkpoint_shards(
                        destination, rows_per_shard=1
                    )
                    return destination

                missing = exported("missing-table")
                manifest_path = missing / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                removed = [
                    shard for shard in manifest["shards"]
                    if shard["table"] == "stages"
                ]
                manifest["shards"] = [
                    shard for shard in manifest["shards"]
                    if shard["table"] != "stages"
                ]
                for shard in removed:
                    (missing / shard["file"]).unlink()
                manifest_path.write_text(
                    json.dumps(manifest, sort_keys=True) + "\n"
                )
                with StateDB(root / "missing.sqlite3") as restored:
                    with self.assertRaisesRegex(
                        ValueError, "every required table"
                    ):
                        restored.import_checkpoint(missing)

                duplicate = exported("duplicate-ordinal")
                manifest_path = duplicate / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                run_shards = [
                    shard for shard in manifest["shards"]
                    if shard["table"] == "runs"
                ]
                self.assertGreaterEqual(len(run_shards), 2)
                run_shards[1]["ordinal"] = run_shards[0]["ordinal"]
                manifest_path.write_text(
                    json.dumps(manifest, sort_keys=True) + "\n"
                )
                with StateDB(root / "duplicate.sqlite3") as restored:
                    with self.assertRaisesRegex(
                        ValueError, "ordinal is duplicated"
                    ):
                        restored.import_checkpoint(duplicate)

                byte_mismatch = exported("byte-mismatch")
                manifest_path = byte_mismatch / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                manifest["shards"][0]["bytes"] += 1
                manifest_path.write_text(
                    json.dumps(manifest, sort_keys=True) + "\n"
                )
                with StateDB(root / "bytes.sqlite3") as restored:
                    with self.assertRaisesRegex(
                        ValueError, "byte count mismatch"
                    ):
                        restored.import_checkpoint(byte_mismatch)

                extra = exported("extra-json")
                (extra / "unindexed.json").write_text("{}\n")
                with StateDB(root / "extra.sqlite3") as restored:
                    with self.assertRaisesRegex(
                        ValueError, "directory closure"
                    ):
                        restored.import_checkpoint(extra)

            with StateDB(root / "oversized-source.sqlite3") as source:
                source.upsert_library(
                    "cublas",
                    catalog={"name": "cuBLAS"},
                    fingerprints=self.fingerprints(),
                )
                source.upsert_repository({
                    "node_id": "R_oversized",
                    "full_name": "public/oversized",
                    "visibility": "public",
                    "head_sha": "a" * 40,
                    "metadata": {"description": "x" * 10_000},
                })
                oversized = root / "oversized"
                with self.assertRaisesRegex(
                    ValueError, "checkpoint row exceeds"
                ):
                    source.export_checkpoint_shards(
                        oversized, target_bytes=2_000
                    )
                self.assertFalse((oversized / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
