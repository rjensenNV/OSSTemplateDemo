"""Deterministic recovery, history, cache, and parallelism acceptance tests.

These fixtures use only local Git repositories.  They never contact GitHub,
write production ``data/``, or invoke the collection entry point.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from collector import config
from collector.pipeline import (
    CollectorPipeline,
    METADATA_BATCH_SIZE,
    NO_LIVE_V2_RELEASE,
    PipelineError,
    RunBudgets,
    _network_task_source_sha256,
)
from collector.planner import build_plan
from collector.repo_cache import RepoCache
from collector.scan import _date_first_use
from collector.scanner_v2 import ScanTask, scan_many
from collector.state import StateDB, canonical_json
from tests.test_req14_pipeline import (
    FakeCitationPipeline,
    FakeDiscovery,
    FakeMetadata,
    fake_scan_runner,
)


def _git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    effective_env = os.environ.copy()
    if env:
        effective_env.update(env)
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=effective_env,
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def _commit(repo: Path, message: str, timestamp: str) -> str:
    stamp = {
        "GIT_AUTHOR_DATE": timestamp,
        "GIT_COMMITTER_DATE": timestamp,
    }
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", message, env=stamp)
    return _git(repo, "rev-parse", "HEAD")


def _fixture_remote(
    root: Path,
    full_name: str,
    files: dict[str, str],
    *,
    timestamp: str = "2020-01-02T03:04:05Z",
) -> tuple[Path, Path, str]:
    source = root / "sources" / full_name.replace("/", "__")
    remote = root / "remotes" / (full_name + ".git")
    source.mkdir(parents=True)
    remote.parent.mkdir(parents=True, exist_ok=True)
    _git(source, "init", "-q", "-b", "main")
    _git(source, "config", "user.name", "REQ-14 Test")
    _git(source, "config", "user.email", "req14@example.invalid")
    for relative, body in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    head = _commit(source, "initial", timestamp)
    _git(root, "init", "--bare", "-q", str(remote))
    _git(source, "remote", "add", "origin", str(remote))
    _git(source, "push", "-q", "-u", "origin", "main")
    _git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
    return source, remote, head


def _cublas() -> list[dict]:
    return [library for library in config.LIBRARIES if library["id"] == "cublas"]


def _stable_outcomes(outcomes) -> list[dict]:
    stable = []
    for outcome in outcomes:
        row = dataclasses.asdict(outcome)
        for volatile in (
            "seconds",
            "cache_hit",
            "cache_bytes",
            "current_tree_triage_seconds",
            "history_dating_seconds",
            "analysis_seconds",
            "git_subprocess_count",
            "network_clone_count",
            "network_fetch_count",
            "network_materialized_bytes",
        ):
            row.pop(volatile)
        stable.append(row)
    return stable


def _artifact_paths(manifest: dict) -> set[str]:
    paths: set[str] = set()

    def visit(value) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "path" and isinstance(item, str):
                    paths.add(item)
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(manifest)
    return paths


def _write_completed_checkpoint(
    root: Path,
    *,
    checkpoint_release_id: str | None = "last-good-release",
    live_release_id: str | None = None,
) -> dict:
    state_path = root / ".state/collector.sqlite3"
    plan = build_plan(
        mode="refresh",
        state_path=state_path,
        data_dir=root / "data",
    )
    with StateDB(root / "checkpoint-source.sqlite3") as source:
        source.create_run(
            "last-good",
            mode="refresh",
            budgets={},
            fingerprints=plan.fingerprints.as_dict(),
            status="running",
        )
        source.finish_run("last-good", status="complete")
        if checkpoint_release_id is not None:
            source.record_release(
                checkpoint_release_id,
                run_id="last-good",
                state_txn="last-good",
                manifest_path="data/v2/manifest.json",
                artifacts=[],
                validation={"valid": True, "errors": []},
                status="published",
            )
        source.export_checkpoint_shards(root / "data/state-checkpoint")
    live = (
        checkpoint_release_id
        if live_release_id is None
        else live_release_id
    )
    if live is not None:
        v2 = root / "data/v2"
        v2.mkdir()
        (v2 / "manifest.json").write_text(
            canonical_json({"release": {"id": live}}) + "\n"
        )
    return plan.fingerprints.as_dict()


def _scan(
    root: Path,
    tasks: list[ScanTask],
    *,
    workers: int,
    cache_name: str,
):
    return scan_many(
        tasks,
        _cublas(),
        root / cache_name,
        workers=workers,
        repo_timeout=60,
        cache_target_bytes=10**9,
        cache_hard_bytes=2 * 10**9,
        remote_template=str(root / "remotes" / "{full_name}.git"),
    )


class HistoryAcceptanceTests(unittest.TestCase):
    def test_notebook_history_does_not_date_from_earlier_saved_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ-14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            notebook = repo / "analysis.ipynb"
            notebook.write_text(json.dumps({
                "cells": [{
                    "cell_type": "code",
                    "source": ["print('complete')"],
                    "outputs": [{"text": ["cuPQC"]}],
                }],
            }))
            _commit(
                repo, "saved output only", "2020-01-02T03:04:05Z"
            )
            notebook.write_text(json.dumps({
                "cells": [
                    {
                        "cell_type": "code",
                        "source": ["print('complete')"],
                        "outputs": [{"text": ["cuPQC"]}],
                    },
                    {
                        "cell_type": "markdown",
                        "source": ["This project targets cuPQC."],
                    },
                ],
            }))
            introduced = _commit(
                repo, "authored target", "2022-03-04T05:06:07Z"
            )

            date, commit, _ai, _agents = _date_first_use(
                str(repo), "cuPQC", ["analysis.ipynb"], False
            )

            self.assertEqual("2022-03-04", date)
            self.assertEqual(introduced, commit)

    def test_first_use_follows_file_rename(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ-14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            old = repo / "src/old.cu"
            old.parent.mkdir()
            old.write_text("#include <cublas_v2.h>\n")
            introduced = _commit(repo, "introduce integration", "2020-01-02T03:04:05Z")
            (repo / "lib").mkdir()
            _git(repo, "mv", "src/old.cu", "lib/current.cu")
            _commit(repo, "rename source", "2022-03-04T05:06:07Z")

            date, commit, _ai, _agents = _date_first_use(
                str(repo), "cublas_v2.h", ["lib/current.cu"], True
            )

            self.assertEqual(date, "2020-01-02")
            self.assertEqual(commit, introduced)

    def test_first_use_after_force_push_ignores_dangling_old_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ-14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            source = repo / "src/use.cu"
            source.parent.mkdir()
            source.write_text("#include <cublas_v2.h>\n")
            old = _commit(repo, "old published history", "2018-01-02T03:04:05Z")

            _git(repo, "checkout", "-q", "--orphan", "replacement")
            _git(repo, "rm", "-q", "-r", "--cached", ".")
            source.write_text("#include <cublas_v2.h>\n")
            replacement = _commit(
                repo, "replacement root history", "2025-06-07T08:09:10Z"
            )
            self.assertNotEqual(old, replacement)

            date, commit, _ai, _agents = _date_first_use(
                str(repo), "cublas_v2.h", ["src/use.cu"], True
            )

            self.assertEqual(date, "2025-06-07")
            self.assertEqual(commit, replacement)


class ScannerAcceptanceTests(unittest.TestCase):
    def test_dispatch_hook_leases_only_worker_slots_before_checkpoint(self):
        class InjectedCoordinatorCrash(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tasks = []
            for index in range(6):
                full_name = "public/queued-%02d" % index
                _source, _remote, head = _fixture_remote(
                    root,
                    full_name,
                    {"src/use.cu": "#include <cublas_v2.h>\n"},
                )
                tasks.append(
                    ScanTask(
                        full_name,
                        head,
                        ("cublas",),
                        estimated_size=1,
                    )
                )
            dispatched = []

            with self.assertRaises(InjectedCoordinatorCrash):
                scan_many(
                    tasks,
                    _cublas(),
                    root / "cache",
                    workers=2,
                    repo_timeout=60,
                    cache_target_bytes=10**9,
                    cache_hard_bytes=2 * 10**9,
                    remote_template=str(
                        root / "remotes" / "{full_name}.git"
                    ),
                    before_task=lambda task: dispatched.append(task.full_name),
                    on_result=lambda _outcome: (
                        _ for _ in ()
                    ).throw(InjectedCoordinatorCrash()),
                )
            self.assertEqual(len(dispatched), 2)

    def test_output_is_deterministic_at_two_and_four_workers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tasks = []
            for index in range(6):
                full_name = "public/repo-%02d" % index
                _source, _remote, head = _fixture_remote(
                    root,
                    full_name,
                    {
                        "src/use.cu": "#include <cublas_v2.h>\n",
                        "src/other-%02d.cc" % index: "int value = %d;\n" % index,
                    },
                )
                tasks.append(ScanTask(full_name, head, ("cublas",)))

            two = _scan(root, tasks, workers=2, cache_name="cache-two")
            four = _scan(root, tasks, workers=4, cache_name="cache-four")

            self.assertEqual(_stable_outcomes(two), _stable_outcomes(four))
            self.assertEqual(
                [outcome.full_name for outcome in two],
                sorted(task.full_name for task in tasks),
            )

    def test_full_and_changed_only_incremental_are_equivalent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_a, _remote_a, head_a = _fixture_remote(
                root,
                "public/a",
                {"src/use.cu": "#include <cublas_v2.h>\n"},
            )
            _source_b, _remote_b, head_b = _fixture_remote(
                root,
                "public/b",
                {"src/use.cu": "#include <cublas_v2.h>\n"},
            )
            initial_tasks = [
                ScanTask("public/a", head_a, ("cublas",)),
                ScanTask("public/b", head_b, ("cublas",)),
            ]
            initial = {
                outcome.full_name: outcome
                for outcome in _scan(
                    root, initial_tasks, workers=2, cache_name="cache-incremental"
                )
            }

            (source_a / "src/unrelated.cc").write_text("int unrelated = 1;\n")
            new_head_a = _commit(
                source_a, "unrelated change", "2024-05-06T07:08:09Z"
            )
            _git(source_a, "push", "-q", "origin", "main")

            changed = _scan(
                root,
                [ScanTask("public/a", new_head_a, ("cublas",))],
                workers=2,
                cache_name="cache-incremental",
            )[0]
            incrementally_materialized = {
                "public/a": changed,
                "public/b": initial["public/b"],
            }
            current_tasks = [
                ScanTask("public/a", new_head_a, ("cublas",)),
                ScanTask("public/b", head_b, ("cublas",)),
            ]
            fully_rebuilt = {
                outcome.full_name: outcome
                for outcome in _scan(
                    root, current_tasks, workers=4, cache_name="cache-full"
                )
            }

            self.assertEqual(
                _stable_outcomes(incrementally_materialized.values()),
                _stable_outcomes(fully_rebuilt.values()),
            )

    def test_scan_many_scavenges_at_startup_and_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                RepoCache, "scavenge", autospec=True, return_value=[]
            ) as scavenge:
                outcomes = scan_many(
                    [],
                    _cublas(),
                    Path(temporary) / "cache",
                    workers=2,
                    cache_target_bytes=10**6,
                    cache_hard_bytes=2 * 10**6,
                )
            self.assertEqual(outcomes, [])
            self.assertEqual(scavenge.call_count, 2)


class StateAcceptanceTests(unittest.TestCase):
    def _seed_verdict(self, state: StateDB) -> None:
        fingerprints = {
            name: name[0] * 64
            for name in (
                "discovery",
                "detector",
                "citation",
                "dating",
                "aggregation",
                "presentation",
                "release",
            )
        }
        state.upsert_library(
            "cublas", catalog={"name": "cuBLAS"}, fingerprints=fingerprints
        )
        state.upsert_repository(
            {
                "node_id": "R_public",
                "full_name": "public/example",
                "visibility": "public",
                "head_sha": "a" * 40,
            }
        )
        state.record_scan_result(
            repository_id="R_public",
            library_id="cublas",
            head_sha="a" * 40,
            detector_fp=fingerprints["detector"],
            classification="confirmed",
            status="clean",
            evidence={"own_source_files": ["src/use.cu"]},
        )

    def test_repeated_crashes_do_not_consume_attempts_for_queued_tasks(self):
        with tempfile.TemporaryDirectory() as temporary:
            with StateDB(Path(temporary) / "state.sqlite3") as state:
                state.create_run(
                    "large-queue",
                    mode="reconcile",
                    budgets={},
                    fingerprints={},
                    status="running",
                )
                task_ids = []
                for index in range(12):
                    node_id = "R_public_%02d" % index
                    full_name = "public/repo-%02d" % index
                    state.upsert_repository({
                        "node_id": node_id,
                        "full_name": full_name,
                        "visibility": "public",
                        "head_sha": "a" * 40,
                    })
                    task_ids.append(state.enqueue_task(
                        "large-queue",
                        "scan",
                        full_name,
                        repository_id=node_id,
                        payload={
                            "repo": full_name,
                            "head_sha": "a" * 40,
                        },
                    ))

                # A coordinator failure affects only the two dispatched worker
                # slots. Their unknown usage fails closed; repeated recovery
                # cannot consume more attempts, and ten queued tasks remain
                # untouched.
                base = time.time()
                for task_id in task_ids[:2]:
                    row = state.lease_task_by_id(
                        task_id,
                        worker="coordinator:0",
                        lease_seconds=1,
                        now_epoch=base,
                    )
                    self.assertIsNotNone(row)
                state.recover_stale_tasks(now_epoch=base + 2)
                for crash in range(1, 3):
                    for task_id in task_ids[:2]:
                        self.assertIsNone(state.lease_task_by_id(
                            task_id,
                            worker="coordinator:%d" % crash,
                            lease_seconds=1,
                            now_epoch=base + crash * 10.0,
                        ))

                rows = {
                    row["task_id"]: row
                    for row in state.connection.execute(
                        "SELECT task_id, status, attempts FROM tasks"
                    )
                }
                self.assertEqual(
                    [rows[task_id]["attempts"] for task_id in task_ids[2:]],
                    [0] * 10,
                )
                self.assertEqual(
                    [rows[task_id]["status"] for task_id in task_ids[2:]],
                    ["pending"] * 10,
                )
                self.assertEqual(
                    [rows[task_id]["attempts"] for task_id in task_ids[:2]],
                    [1, 1],
                )
                self.assertEqual(
                    [rows[task_id]["status"] for task_id in task_ids[:2]],
                    ["failed", "failed"],
                )

                for task_id in task_ids[2:]:
                    row = state.lease_task_by_id(
                        task_id,
                        worker="coordinator:final",
                        lease_seconds=60,
                        now_epoch=base + 100,
                    )
                    self.assertEqual(row["attempts"], 1)
                    state.complete_task(
                        task_id,
                        worker="coordinator:final",
                        result={
                            "status": "clean",
                            "seconds": 0.1,
                            "current_tree_triage_seconds": 0.1,
                            "history_dating_seconds": 0.0,
                            "analysis_seconds": 0.0,
                            "git_subprocess_count": 0,
                            "network_clone_count": 0,
                            "network_fetch_count": 0,
                            "network_materialized_bytes": 0,
                        },
                    )
                completed = state.connection.execute(
                    """
                    SELECT COUNT(*) FROM tasks
                    WHERE task_id IN (%s) AND status='complete'
                    """
                    % ",".join("?" for _ in task_ids[2:]),
                    task_ids[2:],
                ).fetchone()[0]
                self.assertEqual(completed, 10)

    def test_cache_eviction_does_not_erase_sqlite_verdict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with StateDB(root / "state.sqlite3") as state:
                self._seed_verdict(state)
                cache = RepoCache(root / "cache", target_bytes=150, hard_bytes=200)
                now = time.time()
                for index, name in enumerate(("public/old", "public/new")):
                    repository = cache.repo_path(name)
                    repository.mkdir()
                    (repository / "objects").write_bytes(b"x" * 128)
                    cache.metadata_path(name).write_text(
                        json.dumps(
                            {
                                "full_name": name,
                                "last_access": now - (100 if index == 0 else 0),
                            }
                        )
                    )
                    os.utime(
                        repository,
                        (
                            now - (100 if index == 0 else 0),
                            now - (100 if index == 0 else 0),
                        ),
                    )

                removed = cache.enforce_budget()
                verdict = state.connection.execute(
                    """
                    SELECT classification, status FROM scan_results
                    WHERE repository_id='R_public' AND library_id='cublas'
                    """
                ).fetchone()

                self.assertEqual(removed, ["public/old"])
                self.assertFalse(cache.repo_path("public/old").exists())
                self.assertTrue(cache.repo_path("public/new").exists())
                self.assertEqual(tuple(verdict), ("confirmed", "clean"))

    def test_run_lock_and_compatible_resume_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            with StateDB(Path(temporary) / "state.sqlite3") as state:
                self.assertTrue(
                    state.acquire_lock(
                        "collector-network-run",
                        owner="first",
                        lease_seconds=10,
                        now_epoch=100,
                    )
                )
                self.assertFalse(
                    state.acquire_lock(
                        "collector-network-run",
                        owner="second",
                        lease_seconds=10,
                        now_epoch=105,
                    )
                )
                self.assertTrue(
                    state.renew_lock(
                        "collector-network-run",
                        owner="first",
                        lease_seconds=10,
                        now_epoch=105,
                    )
                )
                self.assertFalse(
                    state.renew_lock(
                        "collector-network-run",
                        owner="second",
                        lease_seconds=10,
                        now_epoch=106,
                    )
                )
                self.assertFalse(
                    state.renew_lock(
                        "collector-network-run",
                        owner="first",
                        lease_seconds=10,
                        now_epoch=116,
                    )
                )
                self.assertTrue(
                    state.acquire_lock(
                        "collector-network-run",
                        owner="second",
                        lease_seconds=10,
                        now_epoch=116,
                    )
                )
                self.assertFalse(
                    state.renew_lock(
                        "collector-network-run",
                        owner="first",
                        lease_seconds=10,
                        now_epoch=117,
                    )
                )
                fingerprints = {"engine": "a" * 64}
                budgets = {"max_wall_seconds": 100}
                state.create_run(
                    "interrupted",
                    mode="refresh",
                    budgets=budgets,
                    fingerprints=fingerprints,
                    status="running",
                )
                self.assertEqual(
                    state.resume_compatible_run(
                        mode="refresh",
                        budgets=budgets,
                        fingerprints=fingerprints,
                    ),
                    "interrupted",
                )
                with self.assertRaisesRegex(RuntimeError, "incompatible"):
                    state.resume_compatible_run(
                        mode="refresh",
                        budgets=budgets,
                        fingerprints={"engine": "b" * 64},
                    )
                row = state.connection.execute(
                    "SELECT status FROM runs WHERE run_id='interrupted'"
                ).fetchone()
                self.assertEqual(row["status"], "running")

    def test_pipeline_refuses_incompatible_interrupted_run_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            budgets = RunBudgets(
                max_wall_seconds=300,
                max_scan_repositories=10,
                max_sourcegraph_requests=10,
                max_github_search_requests=10,
                max_graphql_points=100,
                min_graphql_remaining=50,
                max_fetches=10,
                workers=1,
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                state.create_run(
                    "incompatible",
                    mode="onboard",
                    budgets=budgets.to_dict(),
                    fingerprints={"obsolete": True},
                    status="running",
                )

            pipeline = CollectorPipeline(repo_root=root)
            with self.assertRaisesRegex(PipelineError, "incompatible interrupted run"):
                pipeline.run(
                    mode="onboard",
                    library_ids=("cublas",),
                    budgets=budgets,
                )

            with StateDB(root / ".state/collector.sqlite3") as state:
                rows = state.connection.execute(
                    "SELECT run_id, status FROM runs ORDER BY created_at"
                ).fetchall()
                self.assertEqual(
                    [(row["run_id"], row["status"]) for row in rows],
                    [("incompatible", "running")],
                )
            self.assertFalse((root / "data/v2").exists())

    def test_pipeline_reuses_compatible_interrupted_run_id(self):
        class InjectedStop(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            budgets = RunBudgets(
                max_wall_seconds=300,
                max_scan_repositories=10,
                max_sourcegraph_requests=10,
                max_github_search_requests=10,
                max_graphql_points=100,
                min_graphql_remaining=50,
                max_fetches=10,
                workers=1,
            )
            plan = build_plan(
                mode="refresh",
                state_path=root / ".state/collector.sqlite3",
                data_dir=root / "data",
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                state.create_run(
                    "interrupted",
                    mode="onboard",
                    plan={
                        "execution_contract": {
                            "mode": "onboard",
                            "selected_library_ids": ["cublas"],
                            "metadata_batch_size": METADATA_BATCH_SIZE,
                            "network_task_source_sha256": (
                                _network_task_source_sha256()
                            ),
                        }
                    },
                    budgets=budgets.to_dict(),
                    fingerprints=plan.fingerprints.as_dict(),
                    base_release_id=NO_LIVE_V2_RELEASE,
                    status="running",
                )

            pipeline = CollectorPipeline(repo_root=root)
            with mock.patch.object(
                pipeline, "_discover", side_effect=InjectedStop("after resume")
            ):
                with self.assertRaises(InjectedStop):
                    pipeline.run(
                        mode="onboard",
                        library_ids=("cublas",),
                        budgets=budgets,
                    )

            with StateDB(root / ".state/collector.sqlite3") as state:
                rows = state.connection.execute(
                    "SELECT run_id, status FROM runs ORDER BY created_at"
                ).fetchall()
                self.assertEqual(
                    [(row["run_id"], row["status"]) for row in rows],
                    [("interrupted", "failed")],
                )


class PipelineEquivalenceTests(unittest.TestCase):
    @staticmethod
    def _fixture_pipeline(root: Path) -> CollectorPipeline:
        return CollectorPipeline(
            repo_root=root,
            sourcegraph=FakeDiscovery("sourcegraph"),
            github_search=FakeDiscovery("github-code-search"),
            metadata=FakeMetadata(),
            scan_runner=fake_scan_runner,
            citation_pipeline=FakeCitationPipeline(),
        )

    @staticmethod
    def _budgets() -> RunBudgets:
        return RunBudgets(
            max_wall_seconds=300,
            max_scan_repositories=10,
            max_sourcegraph_requests=500,
            max_github_search_requests=500,
            max_graphql_points=100,
            min_graphql_remaining=50,
            max_fetches=10,
            workers=1,
            cache_target_bytes=10**8,
            cache_hard_bytes=2 * 10**8,
        )

    def test_scan_checkpoint_is_atomic_when_journal_commit_crashes(self):
        class InjectedCrash(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            pipeline = self._fixture_pipeline(root)
            original_complete_task = StateDB.complete_task

            def crash_scan_task(
                state,
                task_id,
                *,
                worker,
                result=None,
                now_epoch=None,
            ):
                stage = state.connection.execute(
                    "SELECT stage FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()["stage"]
                if stage == "scan":
                    raise InjectedCrash("before journal completion")
                return original_complete_task(
                    state,
                    task_id,
                    worker=worker,
                    result=result,
                    now_epoch=now_epoch,
                )

            with mock.patch.object(
                StateDB,
                "complete_task",
                autospec=True,
                side_effect=crash_scan_task,
            ):
                with self.assertRaises(InjectedCrash):
                    pipeline.run(
                        mode="onboard",
                        library_ids=("cublas",),
                        budgets=self._budgets(),
                    )

            with StateDB(root / ".state/collector.sqlite3") as state:
                scan_rows = state.connection.execute(
                    "SELECT COUNT(*) FROM scan_results"
                ).fetchone()[0]
                analysis_rows = state.connection.execute(
                    "SELECT COUNT(*) FROM repo_analysis"
                ).fetchone()[0]
                task_status = state.connection.execute(
                    "SELECT status FROM tasks WHERE stage='scan'"
                ).fetchone()[0]
                attempt = state.connection.execute(
                    """
                    SELECT status, usage_complete,
                           network_materialized_bytes
                    FROM scan_attempts
                    """
                ).fetchone()
            self.assertEqual(scan_rows, 0)
            self.assertEqual(analysis_rows, 0)
            self.assertEqual(task_status, "running")
            self.assertEqual(attempt["status"], "complete")
            self.assertEqual(attempt["usage_complete"], 1)
            self.assertEqual(attempt["network_materialized_bytes"], 123)
            self.assertFalse((root / "data/v2").exists())

            recovered = self._fixture_pipeline(root).run(
                mode="onboard",
                library_ids=("cublas",),
                budgets=self._budgets(),
            )
            self.assertEqual(recovered["scanned"], 1)
            with StateDB(root / ".state/collector.sqlite3") as state:
                runs = state.connection.execute(
                    "SELECT run_id, status FROM runs"
                ).fetchall()
                task_status = state.connection.execute(
                    "SELECT status FROM tasks WHERE stage='scan'"
                ).fetchone()[0]
                attempt_usage = state.scan_attempt_usage(
                    recovered["run_id"]
                )
            self.assertEqual(
                [(row["run_id"], row["status"]) for row in runs],
                [(recovered["run_id"], "complete")],
            )
            self.assertEqual(task_status, "complete")
            self.assertEqual(attempt_usage["attempt_count"], 2)
            self.assertEqual(attempt_usage["complete_attempts"], 2)
            self.assertEqual(
                attempt_usage["network_materialized_bytes"], 246
            )

    def test_full_then_incremental_reuses_scan_and_preserves_stable_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            pipeline = self._fixture_pipeline(root)
            budgets = self._budgets()
            full = pipeline.run(
                mode="reconcile", confirm_full=True, budgets=budgets
            )
            full_paths = {
                path
                for path in _artifact_paths(full["manifest"])
                if not path.startswith(("deltas-", "quality-"))
            }
            full_bytes = {
                path: (root / "data/v2" / path).read_bytes()
                for path in full_paths
            }

            incremental = pipeline.run(mode="refresh", budgets=budgets)
            incremental_paths = {
                path
                for path in _artifact_paths(incremental["manifest"])
                if not path.startswith(("deltas-", "quality-"))
            }
            incremental_bytes = {
                path: (root / "data/v2" / path).read_bytes()
                for path in incremental_paths
            }

            self.assertEqual(full["scanned"], 1)
            self.assertEqual(incremental["scanned"], 0)
            self.assertEqual(
                full["manifest"]["totals"], incremental["manifest"]["totals"]
            )
            # Repository/export/citation payloads are content-addressed data and
            # must remain byte-stable. Library indexes intentionally include
            # coverage freshness: a rotating GitHub lane becomes explicitly
            # carried-forward on the following Sourcegraph-only refresh.
            stable_prefixes = (
                "exports/",
                "libraries/",
                "citations/",
            )
            stable_paths = {
                path
                for path in full_paths.intersection(incremental_paths)
                if path.startswith(stable_prefixes)
            }
            self.assertTrue(stable_paths)
            self.assertEqual(
                {path: full_bytes[path] for path in stable_paths},
                {path: incremental_bytes[path] for path in stable_paths},
            )

            full_indexes = {
                item["id"]: item["index"]["path"]
                for item in full["manifest"]["libraries"]
                if item.get("index")
            }
            incremental_indexes = {
                item["id"]: item["index"]["path"]
                for item in incremental["manifest"]["libraries"]
                if item.get("index")
            }
            self.assertEqual(set(full_indexes), set(incremental_indexes))
            coverage_changes = 0
            for library_id in sorted(full_indexes):
                full_index = json.loads(
                    full_bytes[full_indexes[library_id]]
                )
                incremental_index = json.loads(
                    incremental_bytes[incremental_indexes[library_id]]
                )
                full_coverage = full_index.pop("discovery_coverage")
                incremental_coverage = incremental_index.pop(
                    "discovery_coverage"
                )
                self.assertEqual(full_index, incremental_index)
                if full_coverage != incremental_coverage:
                    coverage_changes += 1
                    self.assertFalse(full_coverage["carried_forward"])
                    self.assertTrue(
                        incremental_coverage["carried_forward"]
                    )
            self.assertGreater(coverage_changes, 0)
            warm_scan = incremental["report"]["scan"]
            self.assertGreater(
                warm_scan["eligible_repository_library_pairs"], 0
            )
            self.assertEqual(
                warm_scan["eligible_repository_library_pairs"],
                warm_scan["reusable_repository_library_pairs"],
            )
            self.assertEqual(1.0, warm_scan["result_reuse_rate"])
            self.assertEqual(0, warm_scan["dispatched_repository_tasks"])
            self.assertEqual(0, warm_scan["fetches"])
            self.assertGreater(
                incremental["report"]["publication"]["artifact_count"], 0
            )
            with StateDB(root / ".state/collector.sqlite3") as state:
                stages = {
                    row["stage"]: row["status"]
                    for row in state.connection.execute(
                        "SELECT stage, status FROM stages WHERE run_id=?",
                        (incremental["run_id"],),
                    )
                }
            self.assertEqual("complete", stages["aggregation"])
            self.assertEqual("complete", stages["citations"])
            self.assertEqual("complete", stages["publication"])


class CheckpointRecoveryTests(unittest.TestCase):
    def test_plan_stays_read_only_but_networked_refresh_restores_warm_state(self):
        class ReachedNetworkStage(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            expected_fingerprints = _write_completed_checkpoint(root)
            state_path = root / ".state/collector.sqlite3"

            cold_plan = build_plan(
                mode="refresh",
                state_path=state_path,
                data_dir=root / "data",
            )
            self.assertTrue(cold_plan.cold_state)
            self.assertFalse(state_path.exists())

            pipeline = PipelineEquivalenceTests._fixture_pipeline(root)
            with mock.patch.object(
                pipeline,
                "_discover",
                side_effect=ReachedNetworkStage("warm plan reached discovery"),
            ):
                with self.assertRaises(ReachedNetworkStage):
                    pipeline.run(
                        mode="refresh",
                        budgets=PipelineEquivalenceTests._budgets(),
                    )

            self.assertTrue(state_path.exists())
            self.assertFalse(pipeline._active_plan.cold_state)
            self.assertFalse(pipeline._active_plan.requires_full_confirmation)
            with StateDB(state_path) as restored:
                row = restored.connection.execute(
                    """
                    SELECT fingerprints_json FROM runs
                    WHERE run_id='last-good' AND status='complete'
                    """
                ).fetchone()
            self.assertEqual(json.loads(row["fingerprints_json"]), expected_fingerprints)

    def test_checkpoint_release_mismatch_fails_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            _write_completed_checkpoint(
                root,
                checkpoint_release_id="checkpoint-release",
                live_release_id="different-live-release",
            )

            pipeline = PipelineEquivalenceTests._fixture_pipeline(root)
            with self.assertRaisesRegex(
                PipelineError, "state checkpoint validation failed"
            ):
                pipeline.run(
                    mode="refresh",
                    budgets=PipelineEquivalenceTests._budgets(),
                )

            self.assertEqual(pipeline.sourcegraph.calls, 0)
            self.assertEqual(pipeline.github_search.calls, 0)
            self.assertFalse((root / ".state/collector.sqlite3").exists())
            self.assertEqual(
                "different-live-release",
                json.loads(
                    (root / "data/v2/manifest.json").read_text()
                )["release"]["id"],
            )

    def test_checkpoint_without_published_release_fails_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            _write_completed_checkpoint(
                root,
                checkpoint_release_id=None,
                live_release_id="live-release",
            )

            pipeline = PipelineEquivalenceTests._fixture_pipeline(root)
            with self.assertRaisesRegex(
                PipelineError, "state checkpoint validation failed"
            ):
                pipeline.run(
                    mode="refresh",
                    budgets=PipelineEquivalenceTests._budgets(),
                )

            self.assertEqual(pipeline.sourcegraph.calls, 0)
            self.assertEqual(pipeline.github_search.calls, 0)
            self.assertFalse((root / ".state/collector.sqlite3").exists())

    def test_hash_consistent_private_checkpoint_fails_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").mkdir()
            _write_completed_checkpoint(root)
            checkpoint = root / "data/state-checkpoint"
            manifest_path = checkpoint / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            run_shard = next(
                shard for shard in manifest["shards"] if shard["table"] == "runs"
            )
            shard_path = checkpoint / run_shard["file"]
            content = json.loads(shard_path.read_text())
            content["rows"][0]["plan_json"] = canonical_json(
                {
                    "visibility": "private",
                    "full_name": "secret/internal",
                }
            )
            payload = (canonical_json(content) + "\n").encode("utf-8")
            shard_path.write_bytes(payload)
            run_shard["sha256"] = hashlib.sha256(payload).hexdigest()
            manifest_path.write_text(canonical_json(manifest) + "\n")

            pipeline = PipelineEquivalenceTests._fixture_pipeline(root)
            with self.assertRaisesRegex(
                PipelineError, "state checkpoint validation failed"
            ):
                pipeline.run(
                    mode="refresh",
                    budgets=PipelineEquivalenceTests._budgets(),
                )

            self.assertEqual(pipeline.sourcegraph.calls, 0)
            self.assertEqual(pipeline.github_search.calls, 0)
            self.assertFalse((root / ".state/collector.sqlite3").exists())
            self.assertTrue((root / "data/v2/manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
