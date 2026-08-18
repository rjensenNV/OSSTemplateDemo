import concurrent.futures
import contextlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from collector import repo_cache as repo_cache_module
from collector import scan as scan_module
from collector import scanner_v2
from collector import triage as triage_module
from collector.catalog import REQ14_DIRECT_LIBRARIES
from collector.config import ENV_DUMP_PATH_RE, LIBRARIES
from collector.pipeline import signal_specs
from collector.repo_cache import CacheError, RepoCache
from collector.scan import direct_result_from_files, scan_repo
from collector.scanner_v2 import ScanOutcome, ScanTask, _worker, scan_many
from collector.triage import lfs_evidence_path_relevant, triage_tree


def _git(cwd, *args):
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def _fixture_remote(root, full_name, files):
    source = root / "source" / full_name.replace("/", "__")
    remote = root / "remotes" / (full_name + ".git")
    source.mkdir(parents=True)
    remote.parent.mkdir(parents=True, exist_ok=True)
    _git(source, "init", "-q", "-b", "main")
    _git(source, "config", "user.name", "REQ14 Test")
    _git(source, "config", "user.email", "req14@example.invalid")
    for relpath, body in files.items():
        path = source / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    _git(source, "add", ".")
    _git(source, "commit", "-q", "-m", "fixture")
    _git(root, "init", "--bare", "-q", str(remote))
    _git(source, "remote", "add", "origin", str(remote))
    _git(source, "push", "-q", "-u", "origin", "main")
    _git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
    return source, remote, _git(source, "rev-parse", "HEAD")


class RepoCacheTests(unittest.TestCase):
    @staticmethod
    def _seed_cache(cache, entries):
        total = 0
        now = time.time()
        for index, (full_name, size) in enumerate(entries):
            repo = cache.repo_path(full_name)
            repo.mkdir()
            (repo / "objects.pack").write_bytes(b"x" * size)
            cache.metadata_path(full_name).write_text(json.dumps({
                "full_name": full_name,
                "head_sha": "a" * 40,
                "last_access": now + index,
                "bytes": size,
            }))
            total += size
        cache.usage_path.write_text(json.dumps({"total_bytes": total}))

    def test_current_tree_hydration_reserves_and_pre_evicts(self):
        with tempfile.TemporaryDirectory() as td:
            cache = RepoCache(
                Path(td) / "cache",
                target_bytes=100,
                hard_bytes=100,
                reservation_bytes=80,
            )
            self._seed_cache(
                cache,
                (("public/old", 50), ("public/current", 30)),
            )

            def fake_git(_full_name, *args, **_kwargs):
                if args[0] == "rev-parse":
                    return "true\n"
                self.assertEqual(args[0], "fetch")
                self.assertFalse(cache.repo_path("public/old").exists())
                (cache.repo_path("public/current") / "hydrated.pack").write_bytes(
                    b"h" * 40
                )
                return ""

            with mock.patch.object(cache, "_git_dir", side_effect=fake_git):
                self.assertTrue(
                    cache.ensure_current_tree_blobs_locked(
                        "public/current", "a" * 40
                    )
                )

            self.assertEqual(cache.size_bytes(), 70)
            self.assertLessEqual(cache.size_bytes(), cache.hard_bytes)
            metadata = cache._read_metadata("public/current")
            self.assertNotIn("reserved_growth_bytes", metadata)
            self.assertEqual(metadata["bytes"], 70)

    def test_lfs_probe_does_not_relabel_repository_deadline(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _git(root, "init", "-q", "-b", "main")
            tracked = root / "include" / "cusparse.h"
            tracked.parent.mkdir()
            tracked.write_text("#include <cusparse.h>\n")
            _git(root, "add", ".")
            cache = RepoCache(root / "cache")
            original = Path.read_bytes

            def interrupted(candidate):
                if candidate == tracked:
                    raise TimeoutError(
                        "repository wall deadline exhausted"
                    )
                return original(candidate)

            with mock.patch.object(
                Path,
                "read_bytes",
                autospec=True,
                side_effect=interrupted,
            ):
                with self.assertRaisesRegex(
                    TimeoutError,
                    "repository wall deadline exhausted",
                ):
                    cache._materialize_relevant_lfs(
                        "public/example",
                        root,
                        "a" * 40,
                        ("cusparse",),
                    )

    def test_history_growth_reserves_and_pre_evicts(self):
        with tempfile.TemporaryDirectory() as td:
            cache = RepoCache(
                Path(td) / "cache",
                target_bytes=100,
                hard_bytes=100,
                reservation_bytes=80,
            )
            self._seed_cache(
                cache,
                (("public/old", 50), ("public/current", 30)),
            )

            shallow = [True]

            def fake_git(_full_name, *args, **_kwargs):
                if args[0] == "rev-parse":
                    return (
                        "true\n" if shallow[0] else "false\n"
                    )
                self.assertEqual(args[0], "fetch")
                self.assertFalse(cache.repo_path("public/old").exists())
                (cache.repo_path("public/current") / "history.pack").write_bytes(
                    b"h" * 40
                )
                shallow[0] = False
                return ""

            with mock.patch.object(cache, "_git_dir", side_effect=fake_git):
                cache.ensure_full_history_locked("public/current")

            self.assertEqual(cache.size_bytes(), 70)
            self.assertLessEqual(cache.size_bytes(), cache.hard_bytes)
            self.assertNotIn(
                "reserved_growth_bytes",
                cache._read_metadata("public/current"),
            )

    def test_pinned_older_head_fetch_includes_required_trees(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, remote, old_head = _fixture_remote(
                root,
                "public/moving",
                {"src/version.py": "VERSION = 'old'\n"},
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            (source / "src/version.py").write_text("VERSION = 'new'\n")
            _git(source, "add", ".")
            _git(source, "commit", "-q", "-m", "advance default branch")
            _git(source, "push", "-q", "origin", "main")
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://"
                    + str(root / "remotes" / "{full_name}.git")
                ),
            )
            with cache.checkout("public/moving") as (
                current_worktree,
                current_head,
            ):
                self.assertNotEqual(current_head, old_head)
                self.assertEqual(
                    (current_worktree / "src/version.py").read_text(),
                    "VERSION = 'new'\n",
                )
            with cache.checkout(
                "public/moving", old_head
            ) as (old_worktree, resolved):
                self.assertEqual(resolved, old_head)
                self.assertEqual(
                    (old_worktree / "src/version.py").read_text(),
                    "VERSION = 'old'\n",
                )
                cache.ensure_full_history_locked("public/moving")
                cache.ensure_history_path_blobs_locked(
                    "public/moving", ("src/version.py",)
                )

    def test_unexpected_growth_is_removed_instead_of_persisting_over_hard(self):
        with tempfile.TemporaryDirectory() as td:
            cache = RepoCache(
                Path(td) / "cache",
                target_bytes=50,
                hard_bytes=50,
                reservation_bytes=30,
            )
            self._seed_cache(
                cache,
                (("public/old", 10), ("public/current", 30)),
            )

            def fake_git(_full_name, *args, **_kwargs):
                if args[0] == "rev-parse":
                    return "true\n"
                (cache.repo_path("public/current") / "oversize.pack").write_bytes(
                    b"h" * 40
                )
                return ""

            with mock.patch.object(cache, "_git_dir", side_effect=fake_git):
                with self.assertRaisesRegex(
                    CacheError, "exceeds hard limit"
                ):
                    cache.ensure_full_history_locked("public/current")

            self.assertFalse(cache.repo_path("public/current").exists())
            self.assertLessEqual(cache.size_bytes(), cache.hard_bytes)

    def test_sparse_checkout_preserves_mature_targeted_whole_tree_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            large_paths = (
                "课件/assets/large.bin",
                'mail/Corpus Delikti - "Marc".eml',
                "archive/2024\\contract.png",
            )
            _source, _remote, head = _fixture_remote(
                root,
                "public/targeted",
                {
                    "README.md": "This project targets cuBLASDx.\n",
                    "notes/integration.weird": "cublasdx planned\n",
                    **{
                        path: "\0" * 1_000_100
                        for path in large_paths
                    },
                },
            )
            _git(_remote, "config", "uploadpack.allowFilter", "true")
            library = next(
                lib for lib in LIBRARIES if lib["id"] == "cublasdx"
            )
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    )
                ),
            )
            with cache.checkout("public/targeted", head) as (
                checkout,
                _resolved,
            ):
                self.assertFalse((checkout / "README.md").exists())
                cache.ensure_current_tree_blobs_locked(
                    "public/targeted", _resolved
                )
                self.assertEqual(
                    cache.prune_missing_current_blobs_locked(
                        "public/targeted", checkout, _resolved
                    ),
                    len(large_paths),
                )
                for path in large_paths:
                    self.assertEqual(
                        "",
                        _git(checkout, "ls-files", "--", path),
                    )
                result = scan_repo(
                    "public/targeted",
                    [library],
                    lambda _message: None,
                    checkout=str(checkout),
                    include_history=False,
                )
            large_oid = _git(
                _source,
                "rev-parse",
                "HEAD:课件/assets/large.bin",
            )
            cache._git_dir(
                "public/targeted",
                "cat-file",
                "blob",
                large_oid,
            )
            with cache.checkout("public/targeted", head) as (
                warm_checkout,
                warm_resolved,
            ):
                self.assertFalse(
                    cache.ensure_current_tree_blobs_locked(
                        "public/targeted", warm_resolved
                    )
                )
                self.assertEqual(
                    cache.prune_missing_current_blobs_locked(
                        "public/targeted",
                        warm_checkout,
                        warm_resolved,
                    ),
                    len(large_paths),
                )
                for path in large_paths:
                    self.assertEqual(
                        "",
                        _git(warm_checkout, "ls-files", "--", path),
                    )
            self.assertEqual(
                result["libraries"]["cublasdx"]["classification"],
                "targeted",
            )

    def test_cache_reuses_bare_clone_and_cleans_worktree(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/example",
                {
                    "src/main.cu": "#include <cublas_v2.h>\n",
                    "assets/model.bin": "unrelated binary payload\n",
                },
            )
            _git(_remote, "config", "uploadpack.allowFilter", "true")
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    )
                ),
            )
            with cache.checkout("public/example", head) as (worktree, resolved):
                self.assertEqual(resolved, head)
                self.assertTrue((worktree / "src/main.cu").exists())
                self.assertFalse((worktree / "assets/model.bin").exists())
                self.assertTrue(
                    cache.ensure_current_tree_blobs_locked(
                        "public/example", resolved
                    )
                )
                self.assertTrue(cache.last_network_fetch)
            repo_path = cache.repo_path("public/example")
            mtime = repo_path.stat().st_mtime_ns
            with cache.checkout("public/example", head) as (_worktree, resolved):
                self.assertEqual(resolved, head)
            self.assertEqual(len(cache.entries()), 1)
            self.assertEqual(list(cache.worktrees.iterdir()), [])
            self.assertGreaterEqual(repo_path.stat().st_mtime_ns, mtime)

            # A detector-only rescan at an already-cached HEAD needs no
            # network. Removing the fixture remote makes any fetch fail.
            moved_remote = root / "remotes/public/example.offline"
            _remote.rename(moved_remote)
            with cache.checkout("public/example", head) as (_worktree, resolved):
                self.assertEqual(resolved, head)
                self.assertFalse(
                    cache.ensure_current_tree_blobs_locked(
                        "public/example", resolved
                    )
                )
                self.assertFalse(cache.last_network_fetch)
            self.assertEqual(1, cache.network_clone_count)
            self.assertEqual(1, cache.network_fetch_count)
            self.assertGreater(cache.network_materialized_bytes, 0)

    def test_cache_inventory_does_not_walk_every_bare_repo(self):
        with tempfile.TemporaryDirectory() as td:
            cache = RepoCache(Path(td) / "cache", target_bytes=10_000, hard_bytes=20_000)
            total = 0
            for index in range(50):
                name = "public/repo-%02d" % index
                repo = cache.repo_path(name)
                repo.mkdir()
                size = index + 1
                total += size
                cache.metadata_path(name).write_text(json.dumps({
                    "full_name": name,
                    "head_sha": "a" * 40,
                    "last_access": float(index),
                    "bytes": size,
                }))
            cache.usage_path.write_text(json.dumps({"total_bytes": total}))
            with mock.patch(
                "collector.repo_cache._tree_bytes",
                side_effect=AssertionError("global tree walk"),
            ):
                self.assertEqual(len(cache.entries()), 50)
                self.assertEqual(cache.size_bytes(), total)
                self.assertEqual(cache.enforce_budget(), [])

    def test_history_is_shallow_until_positive_evidence_requests_deepen(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, remote, _head = _fixture_remote(
                root,
                "public/history",
                {"src/main.cu": "int value = 0;\n"},
            )
            for index in (1, 2):
                (source / "src/main.cu").write_text(
                    "int value = %d;\n" % index
                )
                _git(source, "add", ".")
                _git(source, "commit", "-q", "-m", "revision %d" % index)
            _git(source, "push", "-q", "origin", "main")
            head = _git(source, "rev-parse", "HEAD")
            _git(remote, "config", "uploadpack.allowFilter", "true")
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(root / "remotes" / "{full_name}.git")
                ),
            )
            with cache.checkout("public/history", head) as (worktree, _resolved):
                self.assertEqual(
                    _git(worktree, "rev-list", "--count", "HEAD"),
                    "1",
                )
                cache.last_network_fetch = False
                cache.ensure_full_history_locked("public/history")
                self.assertTrue(cache.last_network_fetch)
                self.assertEqual(
                    _git(worktree, "rev-list", "--count", "HEAD"),
                    "3",
                )
                oldest = _git(
                    worktree, "rev-list", "--max-parents=0", "HEAD"
                )
                environment = os.environ.copy()
                environment["GIT_NO_LAZY_FETCH"] = "1"
                tree_probe = subprocess.run(
                    [
                        "git", "-C", str(worktree), "cat-file", "-e",
                        oldest + "^{tree}",
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(
                    tree_probe.returncode,
                    0,
                    "positive history must hydrate rename trees in one fetch",
                )
            (source / "README.md").write_text(
                "This changed full-history cache targets cuBLASDx.\n"
            )
            _git(source, "add", ".")
            _git(source, "commit", "-q", "-m", "new current tree")
            _git(source, "push", "-q", "origin", "main")
            new_head = _git(source, "rev-parse", "HEAD")
            with cache.checkout("public/history", new_head) as (
                worktree,
                resolved,
            ):
                self.assertEqual(resolved, new_head)
                self.assertTrue(
                    cache.ensure_current_tree_blobs_locked(
                        "public/history", resolved
                    )
                )
                self.assertEqual(
                    _git(worktree, "rev-parse", "--is-shallow-repository"),
                    "true",
                )
                self.assertIn(
                    "README.md",
                    _git(
                        worktree,
                        "grep",
                        "--cached",
                        "-l",
                        "-F",
                        "cuBLASDx",
                    ),
                )
                cache.ensure_full_history_locked("public/history")
                self.assertEqual(
                    _git(
                        worktree,
                        "rev-parse",
                        "--is-shallow-repository",
                    ),
                    "false",
                )

    def test_progressive_history_stops_at_reachable_boundary_without_unshallow(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, remote, _head = _fixture_remote(
                root,
                "public/progressive-history",
                {"src/main.cu": "int value = 0;\n"},
            )
            for index in range(1, 71):
                (source / "src/main.cu").write_text(
                    "int value = %d;\n" % index
                )
                _git(source, "add", ".")
                _git(source, "commit", "-q", "-m", "revision %d" % index)
            _git(source, "push", "-q", "origin", "main")
            head = _git(source, "rev-parse", "HEAD")
            boundary = _git(source, "rev-parse", "HEAD~10")
            _git(remote, "config", "uploadpack.allowFilter", "true")
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(root / "remotes" / "{full_name}.git")
                ),
            )
            with cache.checkout(
                "public/progressive-history", head
            ) as (worktree, _resolved):
                with mock.patch.object(
                    cache, "_git_dir", wraps=cache._git_dir
                ) as git_dir:
                    availability = cache.ensure_history_until_locked(
                        "public/progressive-history",
                        required_commits=(boundary,),
                    )
                self.assertFalse(availability.complete)
                self.assertIn(
                    boundary, availability.reachable_commits
                )
                self.assertGreaterEqual(
                    availability.deepen_fetches, 1
                )
                self.assertEqual(
                    _git(
                        worktree,
                        "rev-parse",
                        "--is-shallow-repository",
                    ),
                    "true",
                )
                fetch_calls = [
                    call.args[1:]
                    for call in git_dir.call_args_list
                    if len(call.args) > 1 and call.args[1] == "fetch"
                ]
                self.assertTrue(fetch_calls)
                self.assertTrue(
                    all(
                        "--unshallow" not in call
                        for call in fetch_calls
                    )
                )

    def test_positive_path_history_fetch_is_bounded_and_selective(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, remote, _head = _fixture_remote(
                root,
                "public/path-history",
                {
                    "cmake/positive.cmake": "set(POSITIVE 0)\n",
                    "decoy/history.txt": "decoy 0\n",
                },
            )
            for index in range(1, 7):
                (source / "cmake/positive.cmake").write_text(
                    "set(POSITIVE %d)\n" % index
                )
                (source / "decoy/history.txt").write_text(
                    "decoy %d\n" % index
                )
                _git(source, "add", ".")
                _git(source, "commit", "-q", "-m", "revision %d" % index)
            _git(source, "push", "-q", "origin", "main")
            head = _git(source, "rev-parse", "HEAD")
            _git(remote, "config", "uploadpack.allowFilter", "true")
            _git(
                remote,
                "config",
                "uploadpack.allowAnySHA1InWant",
                "true",
            )
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    )
                ),
            )
            with cache.checkout(
                "public/path-history", head
            ) as (worktree, _resolved):
                cache.ensure_full_history_locked("public/path-history")
                before_refs = _git(worktree, "show-ref")
                original = repo_cache_module._run_command_bytes
                with mock.patch.object(
                    repo_cache_module,
                    "_HISTORY_FETCH_BATCH_OBJECTS",
                    2,
                ), mock.patch.object(
                    repo_cache_module,
                    "_run_command_bytes",
                    wraps=original,
                ) as commands:
                    fetched = cache.ensure_history_path_blobs_locked(
                        "public/path-history",
                        ("cmake/positive.cmake",),
                    )
                fetches = [
                    call
                    for call in commands.call_args_list
                    if "fetch" in call.args[0]
                ]
                self.assertGreaterEqual(fetched, 6)
                self.assertGreaterEqual(len(fetches), 3)
                self.assertTrue(all(
                    call.kwargs["input_bytes"].count(b"\n") <= 2
                    for call in fetches
                ))
                self.assertTrue(all(
                    "--no-write-fetch-head" in call.args[0]
                    and "--stdin" in call.args[0]
                    and "--filter=blob:none" not in call.args[0]
                    for call in fetches
                ))
                self.assertEqual(before_refs, _git(worktree, "show-ref"))

                environment = os.environ.copy()
                environment["GIT_NO_LAZY_FETCH"] = "1"
                positive = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(worktree),
                        "log",
                        "-S",
                        "POSITIVE 0",
                        "--",
                        "cmake/positive.cmake",
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                decoy = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(worktree),
                        "log",
                        "-S",
                        "decoy 0",
                        "--",
                        "decoy/history.txt",
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(positive.returncode, 0, positive.stderr)
                self.assertTrue(positive.stdout)
                self.assertNotEqual(decoy.returncode, 0)

    def test_bare_current_tree_fetches_only_eligible_blobs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, remote, head = _fixture_remote(
                root,
                "public/bare-selective",
                {
                    ".gitattributes": "*.cu text eol=crlf\n",
                    "src/use.cu": "#include <cublas_v2.h>\n",
                    "assets/model.bin": "irrelevant payload\n" * 10_000,
                },
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            _git(
                remote,
                "config",
                "uploadpack.allowAnySHA1InWant",
                "true",
            )
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    )
                ),
            )
            resolved = cache.ensure("public/bare-selective", head)
            with cache.lock("public/bare-selective"):
                entries = cache.prepare_bare_current_tree_locked(
                    "public/bare-selective", resolved
                )
            self.assertEqual(
                {entry[3] for entry in entries},
                {".gitattributes", "assets/model.bin", "src/use.cu"},
            )
            asset_oid = next(
                entry[2]
                for entry in entries
                if entry[3] == "assets/model.bin"
            )
            environment = os.environ.copy()
            environment["GIT_NO_LAZY_FETCH"] = "1"
            unavailable = subprocess.run(
                [
                    "git",
                    "--git-dir",
                    str(cache.repo_path("public/bare-selective")),
                    "cat-file",
                    "--batch-check=%(objectname) %(objecttype)",
                ],
                input=asset_oid + "\n",
                text=True,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(unavailable.returncode, 0, unavailable.stderr)
            self.assertEqual(
                unavailable.stdout.strip(), asset_oid + " missing"
            )

    def test_bare_current_tree_missing_eligible_blob_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, remote, head = _fixture_remote(
                root,
                "public/bare-missing",
                {"src/use.cu": "#include <cublas_v2.h>\n"},
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    )
                ),
            )
            resolved = cache.ensure("public/bare-missing", head)
            remote.rename(remote.with_name(remote.name + ".offline"))
            with cache.lock("public/bare-missing"), self.assertRaises(
                CacheError
            ):
                cache.prepare_bare_current_tree_locked(
                    "public/bare-missing", resolved
                )

    def test_scavenge_and_lru_are_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            cache = RepoCache(Path(td) / "cache", target_bytes=1, hard_bytes=2)
            stale = cache.worktrees / "stale"
            stale.mkdir()
            old = time.time() - 7200
            os.utime(stale, (old, old))
            self.assertEqual(cache.scavenge(), [str(stale)])

    def test_eviction_prefers_cold_rejects_and_preserves_sqlite_verdicts(self):
        with tempfile.TemporaryDirectory() as td:
            cache = RepoCache(
                Path(td) / "cache", target_bytes=3, hard_bytes=3
            )
            self._seed_cache(
                cache,
                (
                    ("public/positive", 1),
                    ("public/unclassified", 1),
                    ("public/cold-reject", 1),
                ),
            )
            verdict_store = cache.root / "state.sqlite"
            verdict_store.write_bytes(b"durable sqlite verdicts")
            self.assertTrue(
                cache.record_outcome_priority(
                    "public/positive",
                    status="match",
                    cache_hit=False,
                    recorded_at=1,
                )
            )
            self.assertTrue(
                cache.record_outcome_priority(
                    "public/cold-reject",
                    status="clean_reject",
                    cache_hit=False,
                    recorded_at=2,
                )
            )
            # Ordinary cache accounting refreshes must retain the coordinator
            # priority instead of silently reverting to plain LRU.
            cache._record_metadata(
                "public/positive",
                head_sha="a" * 40,
                size=1,
                accessed=0,
            )
            cache.target_bytes = 2
            cache.hard_bytes = 2
            self.assertEqual(
                cache.enforce_budget(), ["public/cold-reject"]
            )
            self.assertTrue(cache.repo_path("public/positive").exists())
            self.assertTrue(
                cache.repo_path("public/unclassified").exists()
            )
            self.assertFalse(
                cache.repo_path("public/cold-reject").exists()
            )
            self.assertEqual(
                verdict_store.read_bytes(), b"durable sqlite verdicts"
            )
            self.assertEqual(
                cache._read_metadata("public/positive")[
                    "retention_priority"
                ],
                "positive_history",
            )


class TriageTests(unittest.TestCase):
    def test_detector_relevant_lfs_pointer_fails_closed(self):
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:" + "a" * 64 + "\n"
            "size 1234\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "kernel.cu").write_text(pointer)
            _git(root, "init", "-q", "-b", "main")
            _git(root, "config", "user.name", "REQ14 Test")
            _git(root, "config", "user.email", "req14@example.invalid")
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "lfs pointer")
            cublas = next(
                library
                for library in LIBRARIES
                if library["id"] == "cublas"
            )
            with self.assertRaisesRegex(
                RuntimeError, "Git LFS object is unavailable"
            ):
                triage_tree(root, [cublas], inventory_all=True)

    def test_irrelevant_lfs_pointer_does_not_block_triage(self):
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:" + "a" * 64 + "\n"
            "size 1234\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "artifact.exe").write_text(pointer)
            (root / "kernel.cu").write_text("int main() { return 0; }\n")
            _git(root, "init", "-q", "-b", "main")
            _git(root, "config", "user.name", "REQ14 Test")
            _git(root, "config", "user.email", "req14@example.invalid")
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "irrelevant lfs pointer")
            cublas = next(
                library
                for library in LIBRARIES
                if library["id"] == "cublas"
            )
            result = triage_tree(
                root, [cublas], inventory_all=True
            )
        self.assertEqual((), result.candidate_library_ids)

    def test_generated_cubin_lfs_pointer_does_not_block_or_classify(self):
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:" + "a" * 64 + "\n"
            "size 280380\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            generated = (
                root / "cpp" / "product" / "kernels" / "cubin"
                / "xqa_kernel_cubin.cpp"
            )
            generated.parent.mkdir(parents=True)
            generated.write_text(pointer)
            (generated.parent / "generated_wrapper.cu").write_text(
                "#include <cublas_v2.h>\n"
            )
            (root / "src").mkdir()
            (root / "src" / "main.cpp").write_text(
                "int main() { return 0; }\n"
            )
            _git(root, "init", "-q", "-b", "main")
            _git(root, "config", "user.name", "REQ14 Test")
            _git(root, "config", "user.email", "req14@example.invalid")
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "generated cubin pointer")
            cublas = next(
                library
                for library in LIBRARIES
                if library["id"] == "cublas"
            )
            result = triage_tree(
                root, [cublas], inventory_all=True
            )
        self.assertEqual((), result.candidate_library_ids)
        self.assertEqual(
            "",
            result.current_text[
                "cpp/product/kernels/cubin/xqa_kernel_cubin.cpp"
            ],
        )
        self.assertEqual(
            "",
            result.current_text[
                "cpp/product/kernels/cubin/generated_wrapper.cu"
            ],
        )

    def test_dockerfile_image_lfs_pointer_is_not_a_manifest(self):
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:" + "b" * 64 + "\n"
            "size 101520\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            image = root / "docs" / "Dockerfile.png"
            image.parent.mkdir(parents=True)
            image.write_text(pointer)
            _git(root, "init", "-q", "-b", "main")
            _git(root, "config", "user.name", "REQ14 Test")
            _git(root, "config", "user.email", "req14@example.invalid")
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "dockerfile screenshot")
            cublas = next(
                library
                for library in LIBRARIES
                if library["id"] == "cublas"
            )
            result = triage_tree(
                root, [cublas], inventory_all=True
            )
        self.assertEqual((), result.candidate_library_ids)
        self.assertEqual("", result.current_text["docs/Dockerfile.png"])
        self.assertTrue(triage_module._eligible("Dockerfile.cuda"))
        self.assertFalse(triage_module._eligible("Dockerfile.png"))

    def test_cubin_segment_is_exact_and_does_not_hide_authored_source(self):
        self.assertTrue(
            triage_module._eligible("src/cubinformation/kernel.cu")
        )
        self.assertFalse(
            triage_module._eligible("src/cubin/kernel.cu")
        )

    def test_broad_token_regex_is_factored_and_case_normalized(self):
        token_ids, token_re, *_unused = triage_module._triage_indexes(
            LIBRARIES
        )
        self.assertFalse(token_re.flags & triage_module.re.IGNORECASE)
        for token in token_ids:
            with self.subTest(token=token):
                match = token_re.search("prefix " + token + " suffix")
                self.assertIsNotNone(match)
                self.assertEqual(match.group(0), token)
        prefix_match = token_re.search("cub/fixture.hpp")
        self.assertEqual(prefix_match.group(0), "cub/")

    def test_inventory_reads_large_blob_sets_in_bounded_batches(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            for index in range(3):
                (repo / ("file-%d.txt" % index)).write_text(
                    ("payload-%d-" % index) * 4
                )
            _git(repo, "add", ".")
            original = triage_module._run_command_bytes
            with mock.patch.object(
                triage_module,
                "_INVENTORY_BATCH_BYTES",
                16,
            ), mock.patch.object(
                triage_module,
                "_INVENTORY_BATCH_OBJECTS",
                1,
            ), mock.patch.object(
                triage_module,
                "_run_command_bytes",
                wraps=original,
            ) as commands:
                result = triage_tree(
                    repo,
                    [lib for lib in LIBRARIES if lib["id"] == "cublas"],
                    inventory_all=True,
                )
            content_batches = [
                call
                for call in commands.call_args_list
                if call.args[0][-1] == "--batch"
            ]
            check_batches = [
                call
                for call in commands.call_args_list
                if call.args[0][-1].startswith("--batch-check=")
            ]
            self.assertEqual(len(check_batches), 3)
            self.assertTrue(all(
                call.kwargs["input_bytes"].count(b"\n") == 1
                for call in check_batches
            ))
            self.assertEqual(len(content_batches), 3)
            self.assertTrue(all(
                call.kwargs["env"]["GIT_NO_LAZY_FETCH"] == "1"
                for call in check_batches + content_batches
            ))
            self.assertEqual(
                set(result.current_text),
                {"file-0.txt", "file-1.txt", "file-2.txt"},
            )

    def test_bare_triage_matches_checkout_crlf_and_direct_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, remote, head = _fixture_remote(
                root,
                "public/bare-parity",
                {
                    ".gitattributes": "*.cu text eol=crlf\n",
                    "src/use.cu": "#include <cublas_v2.h>\n",
                    "src/local.cu": '#include "cudnn.h"\n',
                    "src/cudnn.h": "#pragma once\n",
                    "third_party/copied.cu": "#include <nccl.h>\n",
                    "generated/output.cu": "#include <cufft.h>\n",
                    "notebook.ipynb": json.dumps({
                        "cells": [
                            {
                                "cell_type": "code",
                                "source": ["import cudf\n"],
                                "outputs": [{
                                    "text": ["#include <cutlass/cutlass.h>"]
                                }],
                            }
                        ]
                    }),
                    "CITATION.cff": "cff-version: 1.2.0\n",
                },
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            _git(
                remote,
                "config",
                "uploadpack.allowAnySHA1InWant",
                "true",
            )
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    )
                ),
            )
            resolved = cache.ensure("public/bare-parity", head)
            with cache.lock("public/bare-parity"):
                entries = cache.prepare_bare_current_tree_locked(
                    "public/bare-parity", resolved
                )
                with mock.patch.object(
                    triage_module,
                    "_supports_batch_nul_output",
                    return_value=False,
                ), self.assertRaises(
                    triage_module.BareTriageRequiresWorktree
                ):
                    triage_tree(
                        cache.repo_path("public/bare-parity"),
                        REQ14_DIRECT_LIBRARIES,
                        full_name="public/bare-parity",
                        bare_git_dir=cache.repo_path("public/bare-parity"),
                        bare_head=resolved,
                        bare_entries=entries,
                    )
                if not triage_module._supports_batch_nul_output(
                    cache.repo_path("public/bare-parity")
                ):
                    self.skipTest(
                        "Git lacks NUL-delimited filtered batch output"
                    )
                commands = []
                with mock.patch.object(
                    scan_module,
                    "_record_git_subprocess",
                    side_effect=lambda command: commands.append(
                        tuple(command)
                    ),
                ):
                    bare = triage_tree(
                        cache.repo_path("public/bare-parity"),
                        REQ14_DIRECT_LIBRARIES,
                        full_name="public/bare-parity",
                        bare_git_dir=cache.repo_path("public/bare-parity"),
                        bare_head=resolved,
                        bare_entries=entries,
                    )
            filtered_batches = [
                command
                for command in commands
                if (
                    "cat-file" in command
                    and "--filters" in command
                    and "--batch" in command
                )
            ]
            self.assertEqual(len(filtered_batches), 1, filtered_batches)
            self.assertIn("-Z", filtered_batches[0])
            self.assertFalse(any(
                argument.startswith("--path=")
                for command in commands
                for argument in command
            ))
            with cache.checkout(
                "public/bare-parity", resolved
            ) as (worktree, _resolved):
                self.assertIn(b"\r\n", (worktree / "src/use.cu").read_bytes())
                materialized = triage_tree(
                    worktree,
                    REQ14_DIRECT_LIBRARIES,
                    full_name="public/bare-parity",
                )
            for field in (
                "candidate_library_ids",
                "direct_files",
                "signal_files",
                "citation_cff",
                "files_examined",
                "bytes_examined",
                "skipped_large",
            ):
                self.assertEqual(
                    getattr(bare, field),
                    getattr(materialized, field),
                    field,
                )
            self.assertEqual(
                dict(bare.current_text),
                dict(materialized.current_text),
            )

    def test_bare_triage_large_and_binary_policy_matches_checkout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, remote, head = _fixture_remote(
                root,
                "public/bare-policy",
                {
                    "src/large.cu":
                        "#include <cublas_v2.h>\n" + ("x" * 100),
                    "src/binary.cu":
                        "\0#include <cudnn.h>\n",
                    "third_party/large.cu":
                        "#include <nccl.h>\n" + ("y" * 100),
                    "src/clean.cu": "int main() { return 0; }\n",
                },
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            _git(
                remote,
                "config",
                "uploadpack.allowAnySHA1InWant",
                "true",
            )
            cache = RepoCache(
                root / "cache",
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
                remote_template=(
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    )
                ),
            )
            resolved = cache.ensure("public/bare-policy", head)
            with mock.patch.object(
                triage_module, "MAX_SOURCE_BYTES", 40
            ), mock.patch.object(
                triage_module, "MAX_OWN_SOURCE_BYTES", 60
            ):
                with cache.lock("public/bare-policy"):
                    entries = cache.prepare_bare_current_tree_locked(
                        "public/bare-policy", resolved
                    )
                    bare = triage_tree(
                        cache.repo_path("public/bare-policy"),
                        REQ14_DIRECT_LIBRARIES,
                        full_name="public/bare-policy",
                        bare_git_dir=cache.repo_path("public/bare-policy"),
                        bare_head=resolved,
                        bare_entries=entries,
                    )
                with cache.checkout(
                    "public/bare-policy", resolved
                ) as (worktree, _resolved):
                    materialized = triage_tree(
                        worktree,
                        REQ14_DIRECT_LIBRARIES,
                        full_name="public/bare-policy",
                    )
            for field in (
                "candidate_library_ids",
                "direct_files",
                "signal_files",
                "citation_cff",
                "files_examined",
                "bytes_examined",
                "skipped_large",
            ):
                self.assertEqual(
                    getattr(bare, field),
                    getattr(materialized, field),
                    field,
                )
            self.assertEqual(
                dict(bare.current_text),
                dict(materialized.current_text),
            )
            self.assertEqual(bare.direct_files, {})
            self.assertEqual(bare.skipped_large, 1)

    def test_in_memory_grep_matches_every_live_git_grep_shape(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            files = {
                "README.md": "Plans target cuBLASDx.\n",
                "src/use.cu": "#include   <cublasdx.hpp>\n",
                "requirements.txt": "# nvidia-dali\nnvidia-dali-cuda120\n",
                "nested/dev-requirements.in": "nvidia-dali\n",
                "notes/integration.weird": "cufftdx planned\n",
            }
            for relative, body in files.items():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            inventory = triage_tree(
                repo,
                [lib for lib in LIBRARIES if lib["id"] == "cublasdx"],
                inventory_all=True,
            )
            commands = [
                (
                    "grep", "--cached", "-I", "-l", "-iE",
                    r"include[[:space:]]*[<\"]([^>\"]*/)?cublasdx.hpp[>\"]",
                    "--", "*.cu",
                ),
                (
                    "grep", "--cached", "-I", "-n", "-F",
                    "nvidia-dali", "--", "requirements.txt",
                ),
                (
                    "grep", "--cached", "-h", "-i", "-F",
                    "cuBLASDx", "--", "README.md",
                ),
                (
                    "grep", "--cached", "-I", "-l", "-F",
                    "nvidia-dali", "--", "*requirements*",
                ),
                (
                    "grep", "--cached", "-I", "-l", "-i", "-e",
                    "cufftdx",
                ),
            ]
            with scan_module.current_tree_inventory(
                repo, inventory.current_text
            ):
                for command in commands:
                    actual = scan_module._git(str(repo), *command).splitlines()
                    expected = subprocess.run(
                        ["git", "-C", str(repo), *command],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertIn(expected.returncode, (0, 1), expected.stderr)
                    self.assertEqual(
                        expected.stdout.splitlines(),
                        actual,
                        command,
                    )
                with self.assertRaisesRegex(
                    RuntimeError, "BRE-special"
                ):
                    scan_module._git(
                        str(repo), "grep", "--cached", "-l", "-e", "x+y"
                    )

    def test_all_reviewed_cpp_extensions_are_discovered_and_scanned(self):
        extensions = ("hxx", "inc", "inl", "ipp", "tpp")
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            for extension in extensions:
                (repo / ("use." + extension)).write_text(
                    "#include <cublas_v2.h>\n"
                )
            _git(repo, "add", ".")
            cublas = [
                lib for lib in LIBRARIES if lib["id"] == "cublas"
            ]
            result = triage_tree(repo, cublas)
            self.assertEqual(
                set(result.direct_files["cublas"]),
                {"use." + extension for extension in extensions},
            )
            declared = set(signal_specs(cublas[0])[0].extensions)
            self.assertTrue(set(extensions).issubset(declared))

    def test_header_names_require_exact_path_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "collision.cu").write_text(
                "#include <fakecublas.h>\n"
                "#include <mycudnn.h>\n"
                "#include <cutlass/cutlass.h.backup>\n"
            )
            _git(repo, "add", ".")
            selected = [
                lib for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] in {"cublas", "cudnn", "cutlass"}
            ]
            result = triage_tree(repo, selected)
            self.assertEqual(result.direct_files, {})

    def test_one_pass_direct_evidence_and_exclusions(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            files = {
                "src/use.cu": "#include <cublas_v2.h>\n",
                "src/use.py": "import cudf\n",
                "third_party/x.cu": "#include <nccl.h>\n",
                "generated/y.cu": "#include <cudnn.h>\n",
                "docs/readme.md": "#include <cutlass/cutlass.h>\n",
                ".venv/site-packages/z.py": "import flashinfer\n",
                "src/comment.cu": "// #include <cufft.h>\n",
                "src/block-comment.cu": "/*\n#include <cudnn.h>\n*/\n",
                "src/prefix-collisions.cu": (
                    "#include <fakecublas.h>\n"
                    "#include <mycudnn.h>\n"
                    "#include <cutlass/cutlass.h.backup>\n"
                ),
                "src/docstring.py": '"""example: import cuml"""\n',
                "CITATION.cff": "cff-version: 1.2.0\n",
                "notebook.ipynb": json.dumps({
                    "cells": [
                        {"cell_type": "markdown", "source": ["import cuml"]},
                        {"cell_type": "code", "source": ["import cuvs"]},
                    ]
                }),
            }
            for relpath, body in files.items():
                path = repo / relpath
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            result = triage_tree(repo, REQ14_DIRECT_LIBRARIES)
            self.assertIn("cublas", result.direct_files)
            self.assertIn("cudf", result.direct_files)
            self.assertIn("cuvs", result.direct_files)
            for absent in (
                "nccl", "cudnn", "cutlass", "flashinfer", "cufft", "cuml"
            ):
                self.assertNotIn(absent, result.direct_files)
            self.assertEqual(result.citation_cff, ("CITATION.cff",))

    def test_buildozer_segment_is_build_output_not_evidence(self):
        self.assertIsNotNone(
            ENV_DUMP_PATH_RE.search("nested/.buildozer/src/use.cu")
        )
        self.assertIsNone(ENV_DUMP_PATH_RE.search("buildozer.spec"))
        self.assertIsNone(
            ENV_DUMP_PATH_RE.search("src/buildozer/use.cu")
        )
        self.assertFalse(lfs_evidence_path_relevant(
            ".buildozer/src/use.cu", ("nvshmem",)
        ))
        self.assertTrue(lfs_evidence_path_relevant(
            "src/use.cu", ("nvshmem",)
        ))

        nvshmem = [
            library for library in LIBRARIES
            if library["id"] == "nvshmem"
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            generated = {
                ".buildozer/src/direct.cu": "#include <nvshmem.h>\n",
                ".buildozer/third_party/bundled.cu": (
                    "#include <nvshmem.h>\n"
                ),
                ".buildozer/src/runtime_config.py": (
                    'CUDA_LIBS["nvshmem"] = "libnvshmem_host.so"\n'
                ),
            }
            for relative, source in generated.items():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            _git(repo, "add", ".")
            excluded = scan_repo(
                "public/buildozer-output",
                nvshmem,
                lambda _message: None,
                checkout=str(repo),
                include_history=False,
            )
            self.assertIsNone(excluded)

            authored = repo / "src/use.cu"
            authored.parent.mkdir(parents=True)
            authored.write_text("#include <nvshmem.h>\n")
            _git(repo, "add", ".")
            retained = triage_tree(repo, nvshmem)
            self.assertEqual(
                ("src/use.cu",),
                retained.direct_files["nvshmem"],
            )

    def test_virtual_documents_segment_is_generated_not_evidence(self):
        self.assertIsNotNone(
            ENV_DUMP_PATH_RE.search(
                "notebooks/.virtual_documents/Untitled.ipynb"
            )
        )
        self.assertIsNone(
            ENV_DUMP_PATH_RE.search("notebooks/virtual_documents.ipynb")
        )
        self.assertIsNone(
            ENV_DUMP_PATH_RE.search("src/virtual_documents/use.py")
        )
        self.assertFalse(
            lfs_evidence_path_relevant(
                "notebooks/.virtual_documents/use.py", ("dali",)
            )
        )
        self.assertTrue(
            lfs_evidence_path_relevant("notebooks/use.py", ("dali",))
        )

        dali = [library for library in LIBRARIES if library["id"] == "dali"]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            generated = (
                repo / "notebooks" / ".virtual_documents" / "use.ipynb"
            )
            generated.parent.mkdir(parents=True)
            generated.write_text("not valid JSON: import nvidia.dali\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "generated mirror")
            self.assertEqual(
                {},
                scan_repo(
                    "public/jupyter-generated-mirror",
                    dali,
                    lambda _message: None,
                    checkout=str(repo),
                    include_history=False,
                ),
            )

            generated.unlink()
            authored = repo / "notebooks" / "use.ipynb"
            authored.write_text(json.dumps({
                "cells": [{
                    "cell_type": "code",
                    "source": ["import nvidia.dali\n"],
                }],
                "metadata": {},
                "nbformat": 4,
                "nbformat_minor": 5,
            }))
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "authored notebook")
            retained = scan_repo(
                "public/jupyter-authored-notebook",
                dali,
                lambda _message: None,
                checkout=str(repo),
                include_history=False,
            )
            self.assertEqual(
                "confirmed",
                retained["libraries"]["dali"]["classification"],
            )

    def test_authored_internal_dependency_symlink_is_read_as_evidence(self):
        dali = [library for library in LIBRARIES if library["id"] == "dali"]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            requirements = repo / "requirements"
            requirements.mkdir()
            target = repo / "manifests" / "dali-pins.data"
            target.parent.mkdir()
            target.write_text(
                "nvidia-dali-cuda120==1.50.0\n"
            )
            (requirements / "dali-video.in").symlink_to(
                "../manifests/dali-pins.data"
            )
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "authored manifest link")

            self.assertEqual(
                "nvidia-dali-cuda120==1.50.0\n",
                scan_module._read_evidence_text(
                    str(repo), "requirements/dali-video.in"
                ),
            )

            result = scan_repo(
                "public/authored-manifest-link",
                dali,
                lambda _message: None,
                checkout=str(repo),
                include_history=False,
            )
            self.assertEqual(
                "targeted",
                result["libraries"]["dali"]["classification"],
            )

    def test_dependency_symlink_rejects_escape_cycle_and_excluded_target(self):
        cases = (
            ("escape.in", "../../outside.in", None),
            ("absolute.in", "/tmp/outside.in", None),
            ("cycle-a.in", "cycle-b.in", ("cycle-b.in", "cycle-a.in")),
            (
                "generated.in",
                "../.buildozer/requirements.in",
                ("../.buildozer/requirements.in", "nvidia-dali\n"),
            ),
            (
                "vendor.in",
                "../third_party/requirements.in",
                ("../third_party/requirements.in", "nvidia-dali\n"),
            ),
        )
        for name, target, extra in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                repo = Path(td)
                _git(repo, "init", "-q", "-b", "main")
                _git(repo, "config", "user.name", "REQ14 Test")
                _git(repo, "config", "user.email", "req14@example.invalid")
                manifests = repo / "requirements"
                manifests.mkdir()
                (manifests / name).symlink_to(target)
                if extra is not None:
                    relative, body = extra
                    if name == "cycle-a.in":
                        (manifests / relative).symlink_to(body)
                    else:
                        destination = manifests / relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_text(body)
                _git(repo, "add", ".")
                _git(repo, "commit", "-q", "-m", "unsafe manifest link")

                with self.assertRaises(scan_module._RepoScanFailure):
                    scan_module._read_evidence_text(
                        str(repo), "requirements/" + name
                    )

    def test_dependency_symlink_rejects_untracked_local_shadow(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            requirements = repo / "requirements"
            requirements.mkdir()
            (requirements / "declared.in").symlink_to("local-only.in")
            _git(repo, "add", "requirements/declared.in")
            _git(repo, "commit", "-q", "-m", "manifest link")
            (requirements / "local-only.in").write_text("nvidia-dali\n")

            with self.assertRaises(scan_module._RepoScanFailure):
                scan_module._read_evidence_text(
                    str(repo), "requirements/declared.in"
                )

    def test_buildozer_exclusion_covers_each_band_but_not_authored_files(self):
        dali = [library for library in LIBRARIES if library["id"] == "dali"]
        cases = (
            (
                "confirmed",
                "src/use.py",
                "import nvidia.dali\n",
            ),
            (
                "bundled",
                "requirements.txt",
                "nvidia-dali==1.50.0\n",
            ),
            (
                "targeted",
                "config/backend.cfg",
                "optional_backend=nvidia-dali\n",
            ),
        )
        for expected_band, relative, source in cases:
            with self.subTest(expected_band=expected_band):
                with tempfile.TemporaryDirectory() as td:
                    repo = Path(td)
                    _git(repo, "init", "-q", "-b", "main")
                    _git(repo, "config", "user.name", "REQ14 Test")
                    _git(repo, "config", "user.email", "req14@example.invalid")
                    generated = repo / ".buildozer" / relative
                    generated.parent.mkdir(parents=True, exist_ok=True)
                    generated.write_text(source)
                    _git(repo, "add", ".")
                    _git(repo, "commit", "-q", "-m", "generated")
                    excluded = scan_repo(
                        "public/buildozer-output",
                        dali,
                        lambda _message: None,
                        checkout=str(repo),
                        include_history=False,
                    )
                    self.assertEqual({}, excluded)

                    generated.unlink()
                    authored = repo / relative
                    authored.parent.mkdir(parents=True, exist_ok=True)
                    authored.write_text(source)
                    _git(repo, "add", "-A")
                    _git(repo, "commit", "-q", "-m", "authored")
                    retained = scan_repo(
                        "public/authored-source",
                        dali,
                        lambda _message: None,
                        checkout=str(repo),
                        include_history=False,
                    )
                    self.assertEqual(
                        expected_band,
                        retained["libraries"]["dali"]["classification"],
                    )

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            (repo / "buildozer.spec").write_text(
                'requirements = python3,nvidia-dali\n'
            )
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "buildozer spec")
            retained = scan_repo(
                "public/buildozer-spec",
                dali,
                lambda _message: None,
                checkout=str(repo),
                include_history=False,
            )
            self.assertEqual(
                "targeted",
                retained["libraries"]["dali"]["classification"],
            )

    def test_authored_build_wrapper_can_prove_direct_integration(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            wrapper = repo / "crates/cust_raw/build/cublasXt_wrapper.h"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("#include <cublasXt.h>\n")
            generated = repo / "generated/cufft_wrapper.h"
            generated.parent.mkdir(parents=True)
            generated.write_text("#include <cufft.h>\n")
            _git(repo, "add", ".")
            selected = [
                lib for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] in {"cublasxt", "cufft"}
            ]
            result = triage_tree(repo, selected)
            self.assertEqual(
                result.direct_files["cublasxt"],
                ("crates/cust_raw/build/cublasXt_wrapper.h",),
            )
            self.assertNotIn("cufft", result.direct_files)

    def test_tracked_exact_header_does_not_prove_external_sdk_use(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            local_header = repo / "src/api/cpp/nixl.h"
            local_header.parent.mkdir(parents=True)
            local_header.write_text(
                "#ifndef RIXL_NIXL_H\n#define RIXL_NIXL_H\n"
                "void rixl_local_api(void);\n#endif\n"
            )
            consumer = repo / "src/plugins/ucx/ucx_backend.h"
            consumer.parent.mkdir(parents=True)
            consumer.write_text('#include "nixl.h"\n')
            (repo / "meson.build").write_text(
                "install_headers('src/api/cpp/nixl.h')\n"
            )
            _git(repo, "add", ".")
            nixl = [
                library
                for library in REQ14_DIRECT_LIBRARIES
                if library["id"] == "nixl"
            ]
            result = triage_tree(repo, nixl)
            self.assertNotIn("nixl", result.direct_files)
            self.assertIn(
                "src/plugins/ucx/ucx_backend.h",
                result.signal_files["nixl"],
            )

    def test_local_wrapper_can_still_include_real_sdk_header(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            wrapper = repo / "include/cublasLt.h"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("#include <cublasLt.h>\n")
            consumer = repo / "src/use.cc"
            consumer.parent.mkdir(parents=True)
            consumer.write_text('#include "include/cublasLt.h"\n')
            _git(repo, "add", ".")
            cublaslt = [
                library
                for library in REQ14_DIRECT_LIBRARIES
                if library["id"] == "cublaslt"
            ]
            result = triage_tree(repo, cublaslt)
            self.assertEqual(
                result.direct_files["cublaslt"],
                ("include/cublasLt.h",),
            )

    def test_nested_project_sources_are_excluded_from_adoption_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            files = {
                "pyproject.toml": "[project]\nname='host'\n",
                "src/host.py": "import cudf\n",
                "python/setup.py": "from setuptools import setup\nsetup()\n",
                "python/host/use.py": "import cugraph\n",
                "bundle/deployment/scanpy/source/pyproject.toml": (
                    "[project]\nname='scanpy'\n"
                ),
                "bundle/deployment/scanpy/source/scanpy/use.py": (
                    "import cuml\nimport cudf\n"
                ),
                "bundle/deployment/cvxpy/source/setup.py": (
                    "from setuptools import setup\nsetup()\n"
                ),
                "bundle/deployment/cvxpy/source/cvxpy/solver.py": (
                    "import cuopt\n"
                ),
            }
            for relpath, body in files.items():
                path = repo / relpath
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            selected = [
                library
                for library in REQ14_DIRECT_LIBRARIES
                if library["id"] in {"cudf", "cugraph", "cuml", "cuopt"}
            ]
            result = triage_tree(repo, selected)
            self.assertEqual(
                result.direct_files["cudf"], ("src/host.py",)
            )
            self.assertEqual(
                result.direct_files["cugraph"],
                ("python/host/use.py",),
            )
            self.assertNotIn("cuml", result.direct_files)
            self.assertNotIn("cuopt", result.direct_files)
            self.assertNotIn("cuml", result.signal_files)
            self.assertNotIn("cuopt", result.signal_files)

    def test_nested_first_party_manifests_do_not_hide_direct_use(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            files = {
                "csrc/fftconv/setup.py": (
                    "from setuptools import setup\nsetup()\n"
                ),
                "csrc/fftconv/fftconv_cuda.cu": (
                    "#include <cufftdx.hpp>\n"
                ),
                "lane_ws/src/ufld/setup.py": (
                    "from setuptools import setup\nsetup()\n"
                ),
                "lane_ws/src/ufld/data/dali_data.py": (
                    "import nvidia.dali as dali\n"
                ),
                "Face_detection/python-package/setup.py": (
                    "from setuptools import setup\nsetup()\n"
                ),
                "Face_detection/python-package/insightface/utils/filesystem.py": (
                    "dali = __import__('nvidia.dali', globals(), locals(),"
                    " ['pipeline'])\n"
                ),
            }
            for relpath, body in files.items():
                path = repo / relpath
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            selected = [
                library
                for library in LIBRARIES
                if library["id"] in {"cufftdx", "dali"}
            ]
            result = triage_tree(repo, selected)
            self.assertEqual(
                result.direct_files["cufftdx"],
                ("csrc/fftconv/fftconv_cuda.cu",),
            )
            self.assertEqual(
                result.direct_files["dali"],
                (
                    "Face_detection/python-package/insightface/utils/filesystem.py",
                    "lane_ws/src/ufld/data/dali_data.py",
                ),
            )

    def test_distinctive_copied_non_python_roots_cannot_prove_direct_use(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            copied = {
                "YOLO/YOLO-master/darknet/src/gemm.c":
                    "#include <cublas_v2.h>\n",
                "Paddle/models-develop/ops/random.cu":
                    "#include <curand.h>\n",
                "ollama/ml/backend/ggml/src/ggml-cuda/use.cu":
                    "#include <cublas_v2.h>\n",
                "lib/kokkos/backend/fft.cu":
                    "#include <cufft.h>\n",
                "homework/cuda-samples/Samples/use.cu":
                    "#include <nccl.h>\n",
                "fake_cuda/include/cub/cub.cuh":
                    "#include <cub/cub.cuh>\n",
                "nocuda/cutlass/examples/gemm.cu":
                    "#include <cutlass/cutlass.h>\n",
                "Isaac-GR00T/gr00t/tensorrt/use.cpp":
                    "#include <NvInfer.h>\n",
                "jobspec-conversion/data/example/use.py":
                    "import nvidia.dali\n",
                "src/host.cu":
                    "#include <cublas_v2.h>\n",
            }
            for relpath, body in copied.items():
                path = repo / relpath
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            selected = [
                library
                for library in REQ14_DIRECT_LIBRARIES
                if library["id"] in {
                    "cublas", "curand", "cufft", "nccl", "cub",
                    "cutlass", "tensorrt", "dali",
                }
            ]
            result = triage_tree(repo, selected)
            self.assertEqual(
                result.direct_files,
                {"cublas": ("src/host.cu",)},
            )

    def test_copied_root_signatures_preserve_canonical_repository_units(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            files = {
                "Source/CMakeVersion.cmake": "set(CMake_VERSION 4.2)\n",
                "Modules/CMakeCUDAInformation.cmake":
                    "set(CMAKE_CUDA_COMPILER nvcc)\n",
                "Tests/CudaOnly/use.cu": "#include <cublas_v2.h>\n",
            }
            for relpath, body in files.items():
                path = repo / relpath
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            cublas = [
                library for library in REQ14_DIRECT_LIBRARIES
                if library["id"] == "cublas"
            ]
            copied = triage_tree(
                repo, cublas, full_name="public/cmake-copy"
            )
            canonical = triage_tree(
                repo, cublas, full_name="Kitware/CMake"
            )
            self.assertNotIn("cublas", copied.direct_files)
            self.assertEqual(
                canonical.direct_files["cublas"],
                ("Tests/CudaOnly/use.cu",),
            )

    def test_copied_pytorch_roots_do_not_hide_host_owned_source(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            files = {
                "aten/src/ATen/ATen.h": "#include <cublas_v2.h>\n",
                "torch/CMakeLists.txt": "project(torch)\n",
                "caffe2/CMakeLists.txt": "project(caffe2)\n",
                "easyfhe/use.cu": "#include <cublas_v2.h>\n",
            }
            for relpath, body in files.items():
                path = repo / relpath
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            cublas = [
                library for library in REQ14_DIRECT_LIBRARIES
                if library["id"] == "cublas"
            ]
            copied = triage_tree(
                repo, cublas, full_name="public/easyfhe-copy"
            )
            canonical = triage_tree(
                repo, cublas, full_name="pytorch/pytorch"
            )
            self.assertEqual(
                copied.direct_files["cublas"], ("easyfhe/use.cu",)
            )
            self.assertEqual(
                set(canonical.direct_files["cublas"]),
                {"aten/src/ATen/ATen.h", "easyfhe/use.cu"},
            )

    def test_copied_orb_slam2_lfs_is_excluded_but_canonical_fails_closed(self):
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:" + "c" * 64 + "\n"
            "size 2802\n"
        )
        signature_bodies = {
            "CMakeLists.txt": pointer,
            "LICENSE": "ORB-SLAM2 license\n",
            "README.md": "ORB-SLAM2\n",
            "Examples/Monocular/mono_tum.cc": "int main() {}\n",
            "include/System.h": "#pragma once\n",
            "include/Tracking.h": "#pragma once\n",
            "src/System.cc": "#include <cufft.h>\n",
            "Thirdparty/DBoW2/DBoW2/BowVector.cpp": "namespace DBoW2 {}\n",
        }
        cufft = [
            library for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "cufft"
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            for relative, body in signature_bodies.items():
                path = repo / "ORB_SLAM2" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            host = repo / "host" / "use.cu"
            host.parent.mkdir()
            host.write_text("#include <cufft.h>\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "nested ORB-SLAM2 copy")
            copied = triage_tree(
                repo,
                cufft,
                inventory_all=True,
                full_name="public/robot-workspace",
            )
            self.assertEqual(
                {"cufft": ("host/use.cu",)},
                copied.direct_files,
            )
            aggregate = triage_tree(
                repo,
                cufft,
                inventory_all=True,
                full_name=(
                    "sammydev395/"
                    "yahboomcar_ros2_ws_software"
                ),
            )
            self.assertEqual({}, aggregate.direct_files)
            self.assertEqual((), aggregate.candidate_library_ids)

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            for relative, body in signature_bodies.items():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "canonical ORB-SLAM2")
            with self.assertRaisesRegex(
                RuntimeError,
                "Git LFS object is unavailable: CMakeLists.txt",
            ):
                triage_tree(
                    repo,
                    cufft,
                    inventory_all=True,
                    full_name="raulmur/ORB_SLAM2",
                )

    def test_copied_nccl_signature_and_following_fork_are_not_adopters(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            files = {
                "src/bootstrap.cc": "#include <nccl.h>\n",
                "src/channel.cc": "#include <cublas_v2.h>\n",
                "src/collectives/all_reduce.cc": "#include <nccl.h>\n",
                "src/include/core.h": "#include <nccl.h>\n",
                "host/use.cu": "#include <cublas_v2.h>\n",
            }
            for relpath, body in files.items():
                path = repo / relpath
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            selected = [
                library for library in REQ14_DIRECT_LIBRARIES
                if library["id"] in {"cublas", "nccl"}
            ]
            copied_nccl = triage_tree(
                repo, selected, full_name="public/nccl-copy"
            )
            following_fork = triage_tree(
                repo,
                selected,
                full_name="cz007297/MLIAP-FORK-FOLLOWS-MAIN",
            )
            nccl_derivative = triage_tree(
                repo, selected, full_name="paperg/NCCL_GP"
            )
            self.assertEqual(
                copied_nccl.direct_files["cublas"], ("host/use.cu",)
            )
            self.assertNotIn("nccl", copied_nccl.direct_files)
            self.assertEqual({}, following_fork.direct_files)
            self.assertEqual({}, nccl_derivative.direct_files)

    def test_shared_python_parser_handles_magics_dynamic_and_python2(self):
        source = (
            "!pip install nvidia-dali\n"
            "%load_ext autoreload\n"
            "dali = __import__('nvidia.dali', globals(), locals(),"
            " ['pipeline'])\n"
        )
        self.assertIn(
            "nvidia.dali", scan_module._python_import_modules(source)
        )
        imported, _referenced = (
            scan_module._python_namespace_evidence_from_source(
                source, ("nvidia.dali",), allow_qualified_call=False
            )
        )
        self.assertTrue(imported)
        self.assertIn(
            "nvidia.dali",
            scan_module._python_import_modules(
                "print 'legacy'\nimport nvidia.dali as dali\n"
            ),
        )

    def test_mcp_shaped_embedded_projects_cleanly_reject_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/mcp-shaped",
                {
                    "job/deployment/scanpy/source/pyproject.toml": (
                        "[project]\nname='scanpy'\n"
                    ),
                    "job/deployment/scanpy/source/.gitattributes": (
                        "* text=auto eol=lf\n"
                    ),
                    "job/deployment/scanpy/source/scanpy/use.py": (
                        "import cudf\nimport cugraph\nimport cuml\n"
                    ),
                    "job/deployment/scanpy/source/broken.ipynb": (
                        '{"cells":[{"cell_type":"markdown",'
                        '"source":["cudaq-qec"]}'
                    ),
                    "job/deployment/cvxpy/source/setup.py": (
                        "from setuptools import setup\nsetup()\n"
                    ),
                    "job/deployment/cvxpy/source/cvxpy/solver.py": (
                        "import cuopt\n"
                    ),
                },
            )
            selected = [
                library
                for library in LIBRARIES
                if library["id"] in {"cudaq-qec", "cudaq-solvers"}
            ]
            outcome = scan_many(
                [
                    ScanTask(
                        "public/mcp-shaped",
                        head,
                        ("cudaq-qec", "cudaq-solvers"),
                    )
                ],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )[0]
            self.assertEqual(outcome.status, "clean_reject", outcome.error)
            self.assertIsNone(outcome.error)
            self.assertLess(outcome.git_subprocess_count, 20)

    def test_mature_notebook_ignores_outputs_but_keeps_authored_surfaces(self):
        cupqc = [lib for lib in LIBRARIES if lib["id"] == "cupqc"]
        cases = (
            (
                "output",
                {
                    "cells": [{
                        "cell_type": "code",
                        "source": ["print('complete')"],
                        "outputs": [{"text": ["cuPQC"]}],
                        "metadata": {"cuPQC": True},
                    }],
                    "metadata": {"cuPQC": "saved renderer state"},
                },
                False,
            ),
            (
                "code",
                {"cells": [{
                    "cell_type": "code",
                    "source": ["# configure cuPQC integration"],
                    "outputs": [],
                }]},
                True,
            ),
            (
                "markdown",
                {"cells": [{
                    "cell_type": "markdown",
                    "source": ["This project targets cuPQC."],
                }]},
                True,
            ),
        )
        for label, notebook, expected in cases:
            with self.subTest(surface=label), tempfile.TemporaryDirectory() as td:
                repo = Path(td)
                _git(repo, "init", "-q", "-b", "main")
                _git(repo, "config", "user.name", "REQ14 Test")
                _git(repo, "config", "user.email", "req14@example.invalid")
                (repo / "analysis.ipynb").write_text(json.dumps(notebook))
                _git(repo, "add", ".")
                _git(repo, "commit", "-q", "-m", "fixture")
                triage = triage_tree(repo, cupqc, inventory_all=True)
                self.assertEqual(
                    expected,
                    "cupqc" in triage.candidate_library_ids,
                )
                messages = []
                with scan_module.current_tree_inventory(
                    repo, triage.current_text
                ):
                    result = scan_repo(
                        "public/notebook-" + label,
                        cupqc,
                        messages.append,
                        checkout=str(repo),
                        include_history=False,
                    )
                self.assertEqual([], messages)
                self.assertEqual(expected, bool(result))
                if expected:
                    self.assertEqual(
                        "targeted",
                        result["libraries"]["cupqc"]["classification"],
                    )

    def test_notebook_direct_evidence_is_code_only(self):
        cudf = [
            lib for lib in REQ14_DIRECT_LIBRARIES if lib["id"] == "cudf"
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "analysis.ipynb").write_text(json.dumps({
                "cells": [
                    {
                        "cell_type": "markdown",
                        "source": ["import cudf"],
                    },
                    {
                        "cell_type": "code",
                        "source": ["print('done')"],
                        "outputs": [{"text": ["import cudf"]}],
                    },
                ],
            }))
            _git(repo, "add", ".")
            result = triage_tree(repo, cudf, inventory_all=True)
            self.assertNotIn("cudf", result.direct_files)

            (repo / "analysis.ipynb").write_text(json.dumps({
                "cells": [{
                    "cell_type": "code",
                    "source": ["import cudf"],
                    "outputs": [],
                }],
            }))
            _git(repo, "add", ".")
            result = triage_tree(repo, cudf, inventory_all=True)
            self.assertEqual(
                ("analysis.ipynb",), result.direct_files["cudf"]
            )

    def test_utf8_bom_notebook_preserves_authored_evidence_surfaces(self):
        cupqc = [lib for lib in LIBRARIES if lib["id"] == "cupqc"]
        notebook = "\ufeff" + json.dumps({
            "cells": [{
                "cell_type": "code",
                "source": ["# configure cuPQC integration"],
                "outputs": [{"text": ["ignored output"]}],
            }],
        })
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "analysis.ipynb").write_text(notebook)
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "BOM notebook")
            triage = triage_tree(repo, cupqc, inventory_all=True)
            self.assertIn("cupqc", triage.candidate_library_ids)
            messages = []
            with scan_module.current_tree_inventory(
                repo, triage.current_text
            ):
                result = scan_repo(
                    "public/bom-notebook",
                    cupqc,
                    messages.append,
                    checkout=str(repo),
                    include_history=False,
                )
            self.assertEqual([], messages)
            self.assertEqual(
                "targeted",
                result["libraries"]["cupqc"]["classification"],
            )

    def test_evidence_bearing_malformed_notebook_fails_closed(self):
        cupqc = [lib for lib in LIBRARIES if lib["id"] == "cupqc"]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "irrelevant.ipynb").write_text("{not valid JSON")
            _git(repo, "add", ".")
            result = triage_tree(repo, cupqc, inventory_all=True)
            self.assertNotIn("cupqc", result.candidate_library_ids)

            (repo / "relevant.ipynb").write_text(
                '{"cells":[{"cell_type":"markdown","source":["cuPQC"]}'
            )
            _git(repo, "add", ".")
            with self.assertRaisesRegex(
                RuntimeError, "invalid JSON.*relevant.ipynb"
            ):
                triage_tree(repo, cupqc, inventory_all=True)

    def test_malformed_notebook_encoded_output_and_token_substrings_are_irrelevant(self):
        selected = [
            lib for lib in LIBRARIES if lib["id"] in {"cupqc", "cub"}
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "encoded-output.ipynb").write_text(
                '{"cells":[{"cell_type":"code","source":["print(1)"],'
                '"outputs":[{"data":{"image/png":"'
                + ("A" * 300)
                + "cupqc"
                + ("B" * 300)
                + '"}}]}'
            )
            (repo / "substring.ipynb").write_text(
                '{"cells":[{"cell_type":"markdown",'
                '"source":["recipientes cubiertos"]}'
            )
            _git(repo, "add", ".")
            result = triage_tree(repo, selected, inventory_all=True)
        self.assertNotIn("cupqc", result.candidate_library_ids)
        self.assertNotIn("cub", result.candidate_library_ids)

    def test_large_own_source_is_scanned_and_large_generated_is_irrelevant(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            own = repo / "src/large.cu"
            own.parent.mkdir(parents=True)
            own.write_text(
                ("// padding\n" * 110_000)
                + "#include <cublas_v2.h>\n"
            )
            generated = repo / "generated/large.cpp"
            generated.parent.mkdir(parents=True)
            generated.write_text(
                ("// generated padding\n" * 70_000)
                + "#include <cudnn.h>\n"
            )
            _git(repo, "add", ".")
            selected = [
                lib for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] in {"cublas", "cudnn"}
            ]
            result = triage_tree(repo, selected)
            self.assertIn("cublas", result.direct_files)
            self.assertNotIn("cudnn", result.direct_files)
            self.assertEqual(0, result.skipped_large)

    def test_python2_syntax_keeps_executable_direct_use(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "legacy.py").write_text(
                "import cudf\n"
                "print cudf.DataFrame()\n"
            )
            _git(repo, "add", ".")
            selected = [
                lib for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "cudf"
            ]
            result = triage_tree(repo, selected)
            self.assertEqual(
                set(result.direct_files),
                {"cudf"},
            )

    def test_every_req14_detector_has_positive_and_collision_negative(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            cpp_lines = []
            py_lines = []
            for lib in REQ14_DIRECT_LIBRARIES:
                if lib.get("language") == "python":
                    if lib["id"] == "warp":
                        py_lines.extend(("import warp as wp", "wp.init()"))
                    elif lib["id"] == "morpheus":
                        py_lines.append(
                            "from morpheus.pipeline import Pipeline"
                        )
                    else:
                        py_lines.append("import %s" % lib["import_namespace"])
                    if lib.get("cpp_headers"):
                        cpp_lines.append("#include <%s>" % lib["cpp_headers"][0])
                else:
                    if lib.get("cpp_headers"):
                        cpp_lines.append("#include <%s>" % lib["cpp_headers"][0])
                    else:
                        cpp_lines.append(
                            "#include <%sexample.hpp>"
                            % lib["header_prefixes"][0]
                        )
            (repo / "positive.cu").write_text("\n".join(cpp_lines) + "\n")
            (repo / "positive.py").write_text("\n".join(py_lines) + "\n")
            _git(repo, "add", ".")
            result = triage_tree(repo, REQ14_DIRECT_LIBRARIES)
            self.assertEqual(
                set(result.direct_files),
                {lib["id"] for lib in REQ14_DIRECT_LIBRARIES},
            )

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            cpp_lines = []
            py_lines = []
            for lib in REQ14_DIRECT_LIBRARIES:
                headers = list(lib.get("cpp_headers") or ())
                if not headers and lib.get("header_prefixes"):
                    headers.append(
                        "%scollision.hpp" % lib["header_prefixes"][0]
                    )
                for header in headers:
                    cpp_lines.append("// #include <%s>" % header)
                    cpp_lines.append(
                        "/* #include <%s.backup> */" % header
                    )
                if lib.get("language") == "python":
                    namespace = str(lib["import_namespace"])
                    py_lines.append(
                        "# import %s\nimport %s_collision"
                        % (namespace, namespace.replace(".", "_"))
                    )
            (repo / "collisions.cu").write_text(
                "\n".join(cpp_lines) + "\n"
            )
            (repo / "collisions.py").write_text(
                "\n".join(py_lines) + "\n"
            )
            _git(repo, "add", ".")
            result = triage_tree(repo, REQ14_DIRECT_LIBRARIES)
            self.assertEqual({}, result.direct_files)

    def test_direct_cpp_comment_lexer_preserves_markers_inside_strings(self):
        cublas = [
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "cublas"
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "use.cu").write_text(
                'const char *begin = "/*";\n'
                "#include <cublas_v2.h>\n"
                'const char *end = "*/";\n'
                "/* #include <cublas.h> */\n"
            )
            _git(repo, "add", ".")
            result = triage_tree(repo, cublas)
            self.assertEqual(
                {"cublas": ("use.cu",)},
                result.direct_files,
            )

    def test_python2_fallback_rejects_comment_and_string_api_anchors(self):
        selected = [
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] in {"warp", "morpheus"}
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            path = repo / "use.py"
            path.write_text(
                "import warp as wapi\n"
                "import morpheus as mapi\n"
                "print value\n"
                "# wapi.init()\n"
                "# mapi.pipeline\n"
                'message = "wapi.launch() mapi.stages"\n'
            )
            _git(repo, "add", ".")
            result = triage_tree(repo, selected)
            self.assertEqual({}, result.direct_files)

            path.write_text(
                "import warp as wapi\n"
                "import morpheus as mapi\n"
                "print value\n"
                "wapi.init()\n"
                "pipeline = mapi.pipeline\n"
            )
            _git(repo, "add", ".")
            result = triage_tree(repo, selected)
            self.assertEqual(
                {"warp": ("use.py",), "morpheus": ("use.py",)},
                result.direct_files,
            )

    def test_root_prefix_sdk_headers_do_not_confirm_but_host_use_does(self):
        selected = [
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] in {"cub", "thrust"}
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            files = {
                "cub/device/device_scan.cuh": (
                    "#include <cub/util_device.cuh>\n"
                ),
                "cub/util_device.cuh": "#pragma once\n",
                "thrust/detail/use.h": (
                    "#include <thrust/detail/config.h>\n"
                ),
                "thrust/detail/config.h": "#pragma once\n",
            }
            for relative, body in files.items():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            result = triage_tree(repo, selected)
            self.assertEqual({}, result.direct_files)

            host = repo / "src/host.cu"
            host.parent.mkdir(parents=True)
            host.write_text(
                "#include <cub/util_device.cuh>\n"
                "#include <thrust/detail/config.h>\n"
            )
            _git(repo, "add", ".")
            result = triage_tree(repo, selected)
            self.assertEqual(
                {
                    "cub": ("src/host.cu",),
                    "thrust": ("src/host.cu",),
                },
                result.direct_files,
            )

    def test_every_mature_detector_has_positive_and_collision_negative_golden(self):
        positive = {
            "cufftdx": {"src/use.cu": "#include <cufftdx.hpp>\n"},
            "cublasdx": {"src/use.cu": "#include <cublasdx.hpp>\n"},
            "cusolverdx": {"src/use.cu": "#include <cusolverdx.hpp>\n"},
            "curanddx": {"src/use.cu": "#include <curanddx.hpp>\n"},
            "nvcompdx": {"src/use.cu": "#include <nvcompdx.hpp>\n"},
            "dali": {
                "loader.py": (
                    "import nvidia.dali as dali\n"
                    "pipeline = dali.pipeline.Pipeline()\n"
                )
            },
            "cuquantum": {
                "src/use.cu": "#include <custatevec.h>\n"
            },
            "nvpl": {"src/use.c": "#include <nvpl_blas.h>\n"},
            "nvshmem": {"src/use.cu": "#include <nvshmem.h>\n"},
            "nvmath": {
                "math.py": (
                    "import nvmath\n"
                    "plan = nvmath.fft.fft(x)\n"
                )
            },
            "cupqc": {"src/use.cu": "#include <cuhash.hpp>\n"},
            "ovrtx": {
                "sensor.py": (
                    "import ovrtx\n"
                    "session = ovrtx.Session()\n"
                )
            },
        }
        collisions = {
            "cufftdx": {
                "src/lookalike.cu": "#include <fakecufftdx.hpp>\n"
            },
            "cublasdx": {
                "src/lookalike.cu": "#include <fakecublasdx.hpp>\n"
            },
            "cusolverdx": {
                "src/lookalike.cu": "#include <fakecusolverdx.hpp>\n"
            },
            "curanddx": {
                "src/lookalike.cu": "#include <fakecuranddx.hpp>\n"
            },
            "nvcompdx": {
                "src/lookalike.cu": "#include <fakenvcompdx.hpp>\n"
            },
            "dali": {
                "loader.py": (
                    "# import nvidia.dali\n"
                    "import nvidia.dali_collision as dali\n"
                )
            },
            "cuquantum": {
                "quantum.py": (
                    "# import cuquantum\n"
                    "import cuquantum_collision\n"
                ),
                "src/lookalike.cu": "#include <fakecustatevec.h>\n",
            },
            "nvpl": {
                "src/lookalike.c": "#include <invpl_blas.h>\n"
            },
            "nvshmem": {
                "src/lookalike.cu": "#include <fakenvshmem.h>\n"
            },
            "nvmath": {
                "math.py": "# import nvmath\nimport nvmath_collision\n",
                "CMakeLists.txt": "target_link_libraries(app libnvmath.so)\n",
            },
            "cupqc": {
                "src/lookalike.cu": (
                    "#include <fakecupqc.hpp>\n"
                    "#include <fakecuhash.hpp>\n"
                )
            },
            "ovrtx": {
                "sensor.py": "# import ovrtx\nimport ovrtx_collision\n",
                "src/lookalike.c": "#include <fakeovrtx.h>\n",
            },
        }
        collision_verdicts = {
            library_id: (
                "targeted" if library_id in {"nvpl", "ovrtx"} else None
            )
            for library_id in collisions
        }
        mature = {
            library["id"]: library
            for library in LIBRARIES
            if not library.get("direct_only")
        }
        self.assertEqual(set(mature), set(positive))
        self.assertEqual(set(mature), set(collisions))

        for library_id, library in mature.items():
            with self.subTest(library_id=library_id, verdict="positive"), (
                tempfile.TemporaryDirectory()
            ) as td:
                repo = Path(td)
                _git(repo, "init", "-q", "-b", "main")
                _git(repo, "config", "user.name", "REQ14 Test")
                _git(repo, "config", "user.email", "req14@example.invalid")
                for relative, body in positive[library_id].items():
                    path = repo / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body)
                _git(repo, "add", ".")
                _git(repo, "commit", "-q", "-m", "positive fixture")
                result = scan_repo(
                    "public/mature-positive",
                    [library],
                    lambda _message: None,
                    checkout=str(repo),
                    include_history=False,
                )
                self.assertEqual(
                    "confirmed",
                    result["libraries"][library_id]["classification"],
                )

            with self.subTest(library_id=library_id, verdict="collision"), (
                tempfile.TemporaryDirectory()
            ) as td:
                repo = Path(td)
                _git(repo, "init", "-q", "-b", "main")
                _git(repo, "config", "user.name", "REQ14 Test")
                _git(repo, "config", "user.email", "req14@example.invalid")
                for relative, body in collisions[library_id].items():
                    path = repo / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body)
                _git(repo, "add", ".")
                _git(repo, "commit", "-q", "-m", "collision fixture")
                result = scan_repo(
                    "public/mature-collision",
                    [library],
                    lambda _message: None,
                    checkout=str(repo),
                    include_history=False,
                )
                collision_row = (result or {}).get(
                    "libraries", {}
                ).get(library_id)
                self.assertEqual(
                    collision_verdicts[library_id],
                    (
                        collision_row or {}
                    ).get("classification"),
                )

    def test_warp_requires_distinct_api_and_rejects_local_module_shadow(self):
        warp_libraries = [
            lib for lib in REQ14_DIRECT_LIBRARIES if lib["id"] == "warp"
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "positive.py").write_text(
                "import warp as wp\n"
                "@wp.kernel\n"
                "def add():\n"
                "    i = wp.tid()\n"
            )
            _git(repo, "add", ".")
            self.assertIn(
                "warp", triage_tree(repo, warp_libraries).direct_files
            )

    def test_warp_first_use_dates_api_anchor_not_earlier_bare_import(self):
        warp_libraries = [
            lib for lib in REQ14_DIRECT_LIBRARIES if lib["id"] == "warp"
        ]
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            source = repo / "use.py"
            source.write_text("import warp as wp\n")
            _git(repo, "add", ".")
            _git(
                repo,
                "commit",
                "-q",
                "--date=2020-01-02T03:04:05Z",
                "-m",
                "bare import only",
            )
            source.write_text("import warp as wp\nwp.init()\n")
            _git(repo, "add", ".")
            _git(
                repo,
                "commit",
                "-q",
                "--date=2022-03-04T05:06:07Z",
                "-m",
                "actual Warp API use",
            )
            warp_library = next(
                lib for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "warp"
            )
            row = direct_result_from_files(
                repo, warp_library, ("use.py",)
            )
            self.assertEqual(row["first_integration"], "2022-03-04")

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "warp.py").write_text(
                "def local_mesh_warp():\n"
                "    return None\n"
            )
            (repo / "app.py").write_text(
                "import warp\n"
                "warp.local_mesh_warp()\n"
            )
            _git(repo, "add", ".")
            self.assertNotIn(
                "warp", triage_tree(repo, warp_libraries).direct_files
            )

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            (repo / "legacy.py").write_text(
                "import warp as wp\n"
                "print wp.tid()\n"
            )
            _git(repo, "add", ".")
            self.assertIn(
                "warp", triage_tree(repo, warp_libraries).direct_files
            )


class ScannerV2Tests(unittest.TestCase):
    def test_direct_clean_reject_never_creates_a_worktree(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, remote, head = _fixture_remote(
                root,
                "public/bare-clean",
                {"src/main.cc": "int main() { return 0; }\n"},
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            library = next(
                lib
                for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "cublas"
            )
            with mock.patch.object(
                repo_cache_module.tempfile,
                "mkdtemp",
                side_effect=AssertionError(
                    "clean direct triage must not create a worktree"
                ),
            ):
                outcome = _worker((
                    ScanTask("public/bare-clean", head, ("cublas",)),
                    [library],
                    root / "cache",
                    10**9,
                    2 * 10**9,
                    60,
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    ),
                    None,
                    root / "cache" / "worker.active",
                    5 * 10**8,
                ))
            self.assertEqual(outcome.status, "clean_reject", outcome.error)
            self.assertEqual(outcome.result, {})
            self.assertEqual(
                list((root / "cache" / "worktrees").iterdir()), []
            )

    def test_direct_positive_materializes_and_dates_from_full_history(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, remote, _old_head = _fixture_remote(
                root,
                "public/bare-positive",
                {"src/main.cc": "int main() { return 0; }\n"},
            )
            (source / "src/use.cu").write_text(
                "#include <cublas_v2.h>\n"
            )
            _git(source, "add", ".")
            _git(
                source,
                "-c",
                "user.name=REQ14 Test",
                "-c",
                "user.email=req14@example.invalid",
                "commit",
                "-q",
                "-m",
                "integrate cublas",
            )
            _git(source, "push", "-q", "origin", "main")
            head = _git(source, "rev-parse", "HEAD")
            first_date = _git(
                source, "show", "-s", "--format=%cs", head
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            _git(
                remote,
                "config",
                "uploadpack.allowAnySHA1InWant",
                "true",
            )
            library = next(
                lib
                for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "cublas"
            )
            materialized_triage = triage_tree(
                source, [library], full_name="public/bare-positive"
            )
            expected_row = direct_result_from_files(
                source,
                library,
                materialized_triage.direct_files["cublas"],
            )
            original_mkdtemp = repo_cache_module.tempfile.mkdtemp
            with mock.patch.object(
                repo_cache_module.tempfile,
                "mkdtemp",
                wraps=original_mkdtemp,
            ) as worktree_create:
                outcome = _worker((
                    ScanTask(
                        "public/bare-positive", head, ("cublas",)
                    ),
                    [library],
                    root / "cache",
                    10**9,
                    2 * 10**9,
                    60,
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    ),
                    None,
                    root / "cache" / "worker.active",
                    5 * 10**8,
                ))
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertEqual(worktree_create.call_count, 1)
            row = outcome.result["libraries"]["cublas"]
            self.assertEqual(row["classification"], "confirmed")
            self.assertEqual(row["first_integration"], first_date)
            self.assertEqual(
                row["first_integration_commit"], head[:12]
            )
            self.assertEqual(row, expected_row)

    def test_scan_outcome_reports_measured_stage_timings_and_git_processes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, remote, head = _fixture_remote(
                root,
                "public/observable",
                {"src/use.cu": "#include <cublas_v2.h>\n"},
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            library = next(
                lib
                for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "cublas"
            )
            with mock.patch.object(
                scan_module,
                "_record_git_subprocess",
                wraps=scan_module._record_git_subprocess,
            ) as recorder:
                outcome = _worker((
                    ScanTask(
                        "public/observable", head, ("cublas",)
                    ),
                    [library],
                    root / "cache",
                    10**9,
                    2 * 10**9,
                    60,
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    ),
                    None,
                    root / "cache" / "worker.active",
                    5 * 10**8,
                ))
            measured_git = sum(
                1
                for call in recorder.call_args_list
                if (
                    call.args
                    and call.args[0]
                    and os.path.basename(str(call.args[0][0])) == "git"
                )
            )
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertGreater(
                outcome.current_tree_triage_seconds, 0
            )
            self.assertGreater(outcome.history_dating_seconds, 0)
            self.assertGreater(outcome.analysis_seconds, 0)
            self.assertEqual(
                outcome.git_subprocess_count, measured_git
            )
            self.assertGreater(outcome.git_subprocess_count, 0)
            self.assertLessEqual(
                (
                    outcome.current_tree_triage_seconds
                    + outcome.history_dating_seconds
                    + outcome.analysis_seconds
                ),
                outcome.seconds,
            )

    def test_coordinator_records_cache_priority_from_worker_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, clean_head = _fixture_remote(
                root,
                "public/clean-priority",
                {"src/main.cc": "int main() { return 0; }\n"},
            )
            _source, _remote, positive_head = _fixture_remote(
                root,
                "public/positive-priority",
                {"src/use.cu": "#include <cublas_v2.h>\n"},
            )
            cublas = [
                library
                for library in LIBRARIES
                if library["id"] == "cublas"
            ]
            cache_root = root / "cache"
            outcomes = scan_many(
                [
                    ScanTask(
                        "public/clean-priority", clean_head, ("cublas",)
                    ),
                    ScanTask(
                        "public/positive-priority",
                        positive_head,
                        ("cublas",),
                    ),
                ],
                cublas,
                cache_root,
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )
            self.assertEqual(
                [outcome.status for outcome in outcomes],
                ["clean_reject", "match"],
            )
            cache = RepoCache(
                cache_root,
                target_bytes=10**9,
                hard_bytes=2 * 10**9,
            )
            self.assertEqual(
                cache._read_metadata("public/clean-priority")[
                    "retention_priority"
                ],
                "cold_clean_reject",
            )
            self.assertEqual(
                cache._read_metadata("public/positive-priority")[
                    "retention_priority"
                ],
                "positive_history",
            )

    def test_renamed_pytorch_copy_cannot_trigger_mature_history(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/renamed-pytorch-copy",
                {
                    "aten/src/ATen/ATen.h": "#pragma once\n",
                    "torch/CMakeLists.txt": "project(torch)\n",
                    "caffe2/CMakeLists.txt": "project(caffe2)\n",
                    "CMakeLists.txt": "option(USE_NVSHMEM \"NVSHMEM\" ON)\n",
                    "build_variables.bzl": "NVSHMEM = True\n",
                    "cmake/Summary.cmake": "message(STATUS NVSHMEM)\n",
                    "tools/setup_helpers/cmake.py": "NVSHMEM = 'copied'\n",
                    "easyfhe/_C/_distributed_c10d.pyi":
                        "def _has_nvshmem() -> bool: ...\n",
                    "easyfhe/utils/cpp_extension.py":
                        "NVSHMEM_HOME = '/usr/local/nvshmem'\n",
                    (
                        "easyfhe/distributed/_symmetric_memory/"
                        "_nvshmem_triton.py"
                    ): "NVSHMEM_TEAM_WORLD = 0\n",
                    "torch/csrc/distributed/c10d/symm_mem/"
                    "nvshmem_extension.cu": "#include <nvshmem.h>\n",
                },
            )
            nvshmem = [
                library
                for library in LIBRARIES
                if library["id"] == "nvshmem"
            ]
            outcome = scan_many(
                [
                    ScanTask(
                        "public/renamed-pytorch-copy",
                        head,
                        ("nvshmem",),
                    )
                ],
                nvshmem,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )[0]
            self.assertEqual(
                outcome.status, "clean_reject", outcome.error
            )
            self.assertEqual({}, outcome.result)

    def test_mature_bands_exclude_generated_output_but_keep_authored_and_vendor(self):
        nvshmem = next(
            library
            for library in LIBRARIES
            if library["id"] == "nvshmem"
        )
        cases = (
            (
                {
                    (
                        "project/dist/RecognitionSystem/_internal/"
                        "torch/__init__.py"
                    ): '"nvshmem": "libnvshmem_host.so.*[0-9]"\n',
                },
                None,
            ),
            (
                {
                    "src/runtime_config.py":
                        'CUDA_LIBS["nvshmem"] = "libnvshmem_host.so"\n',
                },
                "targeted",
            ),
            (
                {
                    "third_party/runtime/wrapper.cu":
                        "#include <nvshmem.h>\n",
                },
                "bundled",
            ),
        )
        for files, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as td:
                repo = Path(td)
                _git(repo, "init", "-q", "-b", "main")
                _git(repo, "config", "user.name", "REQ14 Test")
                _git(
                    repo,
                    "config",
                    "user.email",
                    "req14@example.invalid",
                )
                for relative, source in files.items():
                    path = repo / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(source)
                _git(repo, "add", ".")
                _git(repo, "commit", "-q", "-m", "fixture")
                result = scan_repo(
                    "public/generated-band-fixture",
                    [nvshmem],
                    lambda _message: None,
                    checkout=str(repo),
                    include_history=False,
                )
                row = (result or {}).get("libraries", {}).get("nvshmem")
                self.assertEqual(
                    expected,
                    (row or {}).get("classification"),
                )

    def test_pytorch_copy_guard_keeps_canonical_and_host_owned_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            files = {
                "aten/src/ATen/ATen.h": "#pragma once\n",
                "torch/CMakeLists.txt": "project(torch)\n",
                "caffe2/CMakeLists.txt": "project(caffe2)\n",
                "torch/csrc/nvshmem_extension.cu":
                    "#include <nvshmem.h>\n",
                "host/use.cu": "#include <nvshmem.h>\n",
            }
            for relpath, body in files.items():
                path = repo / relpath
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "fixture")
            nvshmem = [
                library
                for library in LIBRARIES
                if library["id"] == "nvshmem"
            ]
            host = scan_repo(
                "public/host-with-pytorch-copy",
                nvshmem,
                lambda _message: None,
                checkout=str(repo),
                include_history=False,
            )
            canonical = scan_repo(
                "msft-mirror-aosp/platform.external.pytorch",
                nvshmem,
                lambda _message: None,
                checkout=str(repo),
                include_history=False,
            )
            self.assertEqual(
                host["libraries"]["nvshmem"]["own_source_files"],
                ["host/use.cu"],
            )
            self.assertEqual(
                set(
                    canonical["libraries"]["nvshmem"][
                        "own_source_files"
                    ]
                ),
                {"host/use.cu", "torch/csrc/nvshmem_extension.cu"},
            )

    def test_internal_extension_and_notebook_magic_survive_mature_scan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/internal-extension",
                {
                    "csrc/fftconv/setup.py":
                        "from setuptools import setup\nsetup()\n",
                    "csrc/fftconv/fftconv_cuda.cu":
                        "#include <cufftdx.hpp>\n",
                    "notebooks/dali.ipynb": json.dumps({
                        "cells": [{
                            "cell_type": "code",
                            "source": [
                                "!pip install nvidia-dali\n",
                                "%load_ext autoreload\n",
                                "import nvidia.dali as dali\n",
                                "pipe = dali.pipeline.Pipeline()\n",
                            ],
                            "outputs": [],
                        }],
                    }),
                    "Face_detection/python-package/setup.py":
                        "from setuptools import setup\nsetup()\n",
                    "Face_detection/python-package/use.py": (
                        "dali = __import__('nvidia.dali', globals(),"
                        " locals(), ['pipeline'])\n"
                    ),
                },
            )
            selected = [
                library
                for library in LIBRARIES
                if library["id"] in {"cufftdx", "dali"}
            ]
            outcome = scan_many(
                [
                    ScanTask(
                        "public/internal-extension",
                        head,
                        ("cufftdx", "dali"),
                    )
                ],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )[0]
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertEqual(
                set(outcome.result["libraries"]), {"cufftdx", "dali"}
            )
            self.assertEqual(
                outcome.result["libraries"]["cufftdx"]["classification"],
                "confirmed",
            )
            self.assertEqual(
                outcome.result["libraries"]["dali"]["classification"],
                "confirmed",
            )
            self.assertEqual(
                set(outcome.result["libraries"]["dali"]["own_source_files"]),
                {
                    "Face_detection/python-package/use.py",
                    "notebooks/dali.ipynb",
                },
            )

    def test_generic_mature_references_reject_base64_and_skill_docs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/generic-collisions",
                {
                    "src/constants.rs":
                        'const ENCODED: &str = "QUpQc2VyaWFsaXplZA==";\n',
                    "plugins/nsight/skills/nvshmem/SKILL.md":
                        "Use NVSHMEM for one-sided communication.\n",
                },
            )
            selected = [
                library
                for library in LIBRARIES
                if library["id"] in {"cupqc", "nvshmem"}
            ]
            outcome = scan_many(
                [
                    ScanTask(
                        "public/generic-collisions",
                        head,
                        ("cupqc", "nvshmem"),
                    )
                ],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )[0]
            self.assertEqual(
                outcome.status, "clean_reject", outcome.error
            )
            self.assertEqual({}, outcome.result)

    def test_registered_concurrent_git_groups_are_all_signaled(self):
        with tempfile.TemporaryDirectory() as td:
            registry = Path(td) / "worker.active"
            registry.write_text("111 222\n111 333\n")
            with mock.patch.object(
                scanner_v2.os, "getpgrp", return_value=999
            ), mock.patch.object(
                scanner_v2.os, "killpg"
            ) as killpg:
                signaled = scanner_v2._signal_registered_process_groups(
                    (registry,), signal.SIGTERM
                )
            self.assertEqual(signaled, {222, 333})
            self.assertEqual(
                {call.args for call in killpg.call_args_list},
                {(222, signal.SIGTERM), (333, signal.SIGTERM)},
            )

    def test_independent_direct_library_dating_runs_concurrently(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, remote, head = _fixture_remote(
                root,
                "public/multi-direct",
                {
                    "src/blas.cu": "#include <cublas_v2.h>\n",
                    "src/dnn.cu": "#include <cudnn.h>\n",
                    "src/comm.cu": "#include <nccl.h>\n",
                    "src/frame.py": "import cudf\n",
                },
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            selected = [
                library for library in LIBRARIES
                if library["id"] in {"cublas", "cudnn", "nccl", "cudf"}
            ]
            rendezvous = threading.Barrier(4, timeout=3)
            threads = set()
            lock = threading.Lock()

            def fake_direct(
                _checkout, library, files, **_dating_options
            ):
                with lock:
                    threads.add(threading.get_ident())
                rendezvous.wait()
                return {
                    "classification": "confirmed",
                    "language": "Python",
                    "first_integration": "2024-01-01",
                    "first_integration_commit": "a" * 12,
                    "own_source_files": list(files),
                    "own_source_file_count": len(files),
                    "vendored_present": False,
                    "ai_on_integration_commit": False,
                    "ai_on_integration_agents": [],
                    "operators": [],
                }

            with mock.patch.object(
                scan_module,
                "direct_result_from_files",
                side_effect=fake_direct,
            ):
                outcome = _worker((
                    ScanTask(
                        "public/multi-direct",
                        head,
                        tuple(library["id"] for library in selected),
                    ),
                    selected,
                    root / "cache",
                    10**9,
                    2 * 10**9,
                    60,
                    "file://" + str(
                        root / "remotes" / "{full_name}.git"
                    ),
                    None,
                    root / "cache" / "worker.active",
                    5 * 10**8,
                ))
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertEqual(len(threads), 4)
            self.assertEqual(
                set(outcome.result["libraries"]),
                {"cublas", "cudnn", "nccl", "cudf"},
            )

    def test_git_timeout_label_names_the_actual_subcommand(self):
        with self.assertRaisesRegex(
            RuntimeError, r"git block timed out after"
        ):
            scan_module._run_command(
                [
                    "git",
                    "-c",
                    "alias.block=!sleep 30",
                    "block",
                ],
                0.1,
            )

    def test_clone_integrity_checks_use_configured_git_timeout(self):
        observed = []

        def complete(command, timeout, env=None):
            observed.append((tuple(command), timeout, env))
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(
            scan_module, "_run_command", side_effect=complete
        ):
            scan_module._verify_clone("/public/cache-checkout")

        self.assertEqual(3, len(observed))
        self.assertEqual(30, observed[0][1])
        self.assertIn("rev-parse", observed[0][0])
        self.assertEqual(scan_module.GIT_TIMEOUT, observed[1][1])
        self.assertIn("fsck", observed[1][0])
        self.assertEqual(scan_module.GIT_TIMEOUT, observed[2][1])
        self.assertIn("commit-graph", observed[2][0])

    def test_unknown_sizes_use_exclusive_serial_safe_lane(self):
        self.assertIsNone(
            ScanTask("public/unknown", "a" * 40, ("cublas",)).estimated_size
        )
        self.assertEqual(
            0,
            ScanTask(
                "public/known-zero",
                "b" * 40,
                ("cublas",),
                estimated_size=0,
            ).estimated_size,
        )

        class RecordingPool:
            instances = []
            lifecycle = []

            def __init__(self, max_workers):
                self.max_workers = max_workers
                self.tasks = []
                self._processes = {}
                self.shutdown_called = False
                self.instances.append(self)
                self.lifecycle.append(("create", max_workers))

            def submit(self, _callable, payload):
                task = payload[0]
                self.tasks.append(task)
                future = concurrent.futures.Future()
                future.set_result(ScanOutcome(
                    full_name=task.full_name,
                    head_sha=task.head_sha,
                    status="clean_reject",
                    result={},
                    seconds=0.0,
                    candidate_library_ids=task.candidate_library_ids,
                ))
                return future

            def shutdown(self, **_kwargs):
                self.shutdown_called = True
                self.lifecycle.append(("shutdown", self.max_workers))

        threshold = 100
        tasks = [
            ScanTask("public/unknown-a", "a" * 40, (), estimated_size=None),
            ScanTask("public/unknown-b", "b" * 40, (), estimated_size=None),
            ScanTask("public/giant", "c" * 40, (), estimated_size=threshold),
            ScanTask("public/normal-a", "d" * 40, (), estimated_size=1),
            ScanTask("public/normal-b", "e" * 40, (), estimated_size=0),
        ]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            scanner_v2.concurrent.futures,
            "ProcessPoolExecutor",
            RecordingPool,
        ):
            outcomes = scan_many(
                tasks,
                [],
                Path(temporary) / "cache",
                workers=4,
                cache_target_bytes=10**6,
                cache_hard_bytes=2 * 10**6,
                giant_threshold_bytes=threshold,
            )

        self.assertEqual(5, len(outcomes))
        self.assertEqual(3, len(RecordingPool.instances))
        unknown_pool, giant_pool, normal_pool = RecordingPool.instances
        self.assertEqual(unknown_pool.max_workers, 1)
        self.assertEqual(giant_pool.max_workers, 1)
        self.assertEqual(normal_pool.max_workers, 3)
        self.assertEqual(
            {"public/normal-a", "public/normal-b"},
            {task.full_name for task in normal_pool.tasks},
        )
        self.assertEqual(
            {"public/unknown-a", "public/unknown-b"},
            {task.full_name for task in unknown_pool.tasks},
        )
        self.assertEqual(
            ["public/unknown-a", "public/unknown-b"],
            [task.full_name for task in unknown_pool.tasks],
        )
        self.assertEqual(
            ["public/giant"],
            [task.full_name for task in giant_pool.tasks],
        )
        self.assertEqual(
            RecordingPool.lifecycle[:4],
            [
                ("create", 1),
                ("shutdown", 1),
                ("create", 1),
                ("create", 3),
            ],
        )
        self.assertCountEqual(
            RecordingPool.lifecycle[4:],
            [("shutdown", 1), ("shutdown", 3)],
        )

    def test_known_giant_overlaps_normals_with_bounded_total_concurrency(self):
        threshold = 100
        unknown_names = {"public/unknown"}
        giant_names = {"public/giant-a", "public/giant-b"}
        normal_names = {
            "public/normal-a",
            "public/normal-b",
            "public/normal-c",
        }
        tasks = [
            ScanTask(
                "public/normal-a", "a" * 40, (), estimated_size=1
            ),
            ScanTask(
                "public/unknown", "b" * 40, (), estimated_size=None
            ),
            ScanTask(
                "public/normal-c", "c" * 40, (), estimated_size=3
            ),
            ScanTask(
                "public/giant-a", "d" * 40, (),
                estimated_size=2 * threshold
            ),
            ScanTask(
                "public/normal-b", "e" * 40, (), estimated_size=2
            ),
            ScanTask(
                "public/giant-b", "f" * 40, (),
                estimated_size=threshold
            ),
        ]
        lock = threading.Lock()
        giant_started = threading.Event()
        normal_started = threading.Event()
        active = set()
        unknown_overlap = []
        known_normal_overlap = [False]
        peak_total = [0]
        peak_giant = [0]
        peak_normal = [0]
        lifecycle = []
        journal = []

        def fake_worker(payload):
            task = payload[0]
            is_giant = task.full_name in giant_names
            is_unknown = task.full_name in unknown_names
            with lock:
                if is_unknown and active:
                    unknown_overlap.append(
                        (task.full_name, tuple(sorted(active)))
                    )
                if not is_unknown and any(
                    name in unknown_names for name in active
                ):
                    unknown_overlap.append(
                        (task.full_name, tuple(sorted(active)))
                    )
                if (
                    is_giant and active & normal_names
                ) or (
                    task.full_name in normal_names
                    and active & giant_names
                ):
                    known_normal_overlap[0] = True
                active.add(task.full_name)
                peak_total[0] = max(peak_total[0], len(active))
                peak_giant[0] = max(
                    peak_giant[0], len(active & giant_names)
                )
                peak_normal[0] = max(
                    peak_normal[0],
                    len(active & normal_names),
                )
            if is_unknown:
                time.sleep(0.01)
            elif is_giant:
                giant_started.set()
                if not normal_started.wait(timeout=2):
                    raise AssertionError("normal lane did not overlap giant")
                time.sleep(0.04)
            else:
                normal_started.set()
                if not giant_started.wait(timeout=2):
                    raise AssertionError("giant lane did not overlap normal")
                time.sleep(0.08)
            with lock:
                active.remove(task.full_name)
            return ScanOutcome(
                full_name=task.full_name,
                head_sha=task.head_sha,
                status="clean_reject",
                result={},
                seconds=0.0,
                candidate_library_ids=task.candidate_library_ids,
            )

        class ThreadBackedPool:
            def __init__(self, max_workers):
                self.max_workers = max_workers
                self._processes = {}
                self.executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_workers
                )
                lifecycle.append(("create", max_workers))

            def submit(self, callable_, payload):
                return self.executor.submit(callable_, payload)

            def shutdown(self, **kwargs):
                self.executor.shutdown(**kwargs)
                lifecycle.append(("shutdown", self.max_workers))

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            scanner_v2.concurrent.futures,
            "ProcessPoolExecutor",
            ThreadBackedPool,
        ), mock.patch.object(
            scanner_v2,
            "_worker",
            side_effect=fake_worker,
        ):
            outcomes = scan_many(
                tasks,
                [],
                Path(temporary) / "cache",
                workers=3,
                cache_target_bytes=10**6,
                cache_hard_bytes=2 * 10**6,
                giant_threshold_bytes=threshold,
                before_task=lambda task: journal.append(
                    ("before", task.full_name)
                ),
                on_result=lambda outcome: journal.append(
                    ("result", outcome.full_name)
                ),
            )

        self.assertEqual(unknown_overlap, [])
        self.assertTrue(known_normal_overlap[0])
        self.assertEqual(peak_giant[0], 1)
        self.assertEqual(peak_normal[0], 2)
        self.assertEqual(peak_total[0], 3)
        self.assertEqual(
            lifecycle[:4],
            [
                ("create", 1),
                ("shutdown", 1),
                ("create", 1),
                ("create", 2),
            ],
        )
        self.assertEqual(
            lifecycle[4:],
            [("shutdown", 1), ("shutdown", 2)],
        )
        self.assertEqual(
            journal[:2],
            [
                ("before", "public/unknown"),
                ("result", "public/unknown"),
            ],
        )
        self.assertEqual(
            len([event for event, _name in journal if event == "before"]),
            len(tasks),
        )
        self.assertEqual(
            len([event for event, _name in journal if event == "result"]),
            len(tasks),
        )
        self.assertEqual(
            [outcome.full_name for outcome in outcomes],
            sorted(task.full_name for task in tasks),
        )

    def test_single_worker_reaps_known_giant_before_normal_lane(self):
        lifecycle = []

        class RecordingPool:
            instances = []

            def __init__(self, max_workers):
                self.max_workers = max_workers
                self.tasks = []
                self._processes = {}
                self.instances.append(self)
                lifecycle.append(("create", max_workers))

            def submit(self, _callable, payload):
                task = payload[0]
                self.tasks.append(task.full_name)
                future = concurrent.futures.Future()
                future.set_result(ScanOutcome(
                    full_name=task.full_name,
                    head_sha=task.head_sha,
                    status="clean_reject",
                    result={},
                    seconds=0.0,
                    candidate_library_ids=task.candidate_library_ids,
                ))
                return future

            def shutdown(self, **_kwargs):
                lifecycle.append(("shutdown", self.max_workers))

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            scanner_v2.concurrent.futures,
            "ProcessPoolExecutor",
            RecordingPool,
        ):
            outcomes = scan_many(
                [
                    ScanTask(
                        "public/normal", "a" * 40, (),
                        estimated_size=1
                    ),
                    ScanTask(
                        "public/giant", "b" * 40, (),
                        estimated_size=100
                    ),
                ],
                [],
                Path(temporary) / "cache",
                workers=1,
                cache_target_bytes=10**6,
                cache_hard_bytes=2 * 10**6,
                giant_threshold_bytes=100,
            )

        self.assertEqual(len(outcomes), 2)
        self.assertEqual(
            [pool.tasks for pool in RecordingPool.instances],
            [["public/giant"], ["public/normal"]],
        )
        self.assertEqual(
            lifecycle,
            [
                ("create", 1),
                ("shutdown", 1),
                ("create", 1),
                ("shutdown", 1),
            ],
        )

    def test_scan_partition_does_not_compare_tasks_for_membership(self):
        class ImmediatePool:
            def __init__(self, max_workers):
                self._processes = {}

            def submit(self, _callable, payload):
                task = payload[0]
                future = concurrent.futures.Future()
                future.set_result(ScanOutcome(
                    full_name=task.full_name,
                    head_sha=task.head_sha,
                    status="clean_reject",
                    result={},
                    seconds=0.0,
                    candidate_library_ids=task.candidate_library_ids,
                ))
                return future

            def shutdown(self, **_kwargs):
                pass

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            scanner_v2.concurrent.futures,
            "ProcessPoolExecutor",
            ImmediatePool,
        ), mock.patch.object(
            ScanTask,
            "__eq__",
            side_effect=AssertionError("quadratic task membership comparison"),
        ):
            outcomes = scan_many(
                [
                    ScanTask(
                        "public/giant", "a" * 40, (),
                        estimated_size=100
                    ),
                    ScanTask(
                        "public/normal", "b" * 40, (),
                        estimated_size=1
                    ),
                    ScanTask(
                        "public/unknown", "c" * 40, (),
                        estimated_size=None
                    ),
                ],
                [],
                Path(temporary) / "cache",
                workers=2,
                cache_target_bytes=10**6,
                cache_hard_bytes=2 * 10**6,
                giant_threshold_bytes=100,
            )

        self.assertEqual(len(outcomes), 3)

    def test_mixed_lanes_share_deadline_cancellation_and_cleanup(self):
        processes = []
        pools = []

        class FakeProcess:
            def __init__(self):
                self.terminated = False
                self.joined = False
                self.killed = False
                processes.append(self)

            def terminate(self):
                self.terminated = True

            def join(self, timeout=None):
                self.joined = timeout == 1

            def is_alive(self):
                return not self.terminated

            def kill(self):
                self.killed = True

        class NeverCompletesPool:
            def __init__(self, max_workers):
                self.max_workers = max_workers
                self.process = FakeProcess()
                self._processes = {max_workers: self.process}
                self.shutdown_calls = []
                pools.append(self)

            def submit(self, _callable, _payload):
                residue = cache_root / "worktrees/deadline-residue"
                residue.mkdir(parents=True, exist_ok=True)
                return concurrent.futures.Future()

            def shutdown(self, **kwargs):
                self.shutdown_calls.append(kwargs)

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            scanner_v2.concurrent.futures,
            "ProcessPoolExecutor",
            NeverCompletesPool,
        ):
            cache_root = Path(temporary) / "cache"
            outcomes = scan_many(
                [
                    ScanTask(
                        "public/giant", "a" * 40, (),
                        estimated_size=100
                    ),
                    ScanTask(
                        "public/normal", "b" * 40, (),
                        estimated_size=1
                    ),
                ],
                [],
                cache_root,
                workers=2,
                cache_target_bytes=10**6,
                cache_hard_bytes=2 * 10**6,
                giant_threshold_bytes=100,
                run_deadline=time.monotonic() + 0.05,
            )

            self.assertEqual(outcomes, [])
            self.assertEqual(
                [pool.max_workers for pool in pools],
                [1, 1],
            )
            self.assertTrue(all(process.terminated for process in processes))
            self.assertTrue(all(process.joined for process in processes))
            self.assertFalse(any(process.killed for process in processes))
            self.assertEqual(
                [pool.shutdown_calls for pool in pools],
                [[{"wait": False, "cancel_futures": True}]] * 2,
            )
            self.assertEqual(
                list((cache_root / "process-groups").iterdir()),
                [],
            )
            self.assertEqual(
                list((cache_root / "worktrees").iterdir()),
                [],
            )

    def test_checkpoint_exception_terminates_in_flight_worker(self):
        processes = []
        pools = []

        class FakeProcess:
            def __init__(self):
                self.terminated = False
                self.joined = False
                processes.append(self)

            def terminate(self):
                self.terminated = True

            def join(self, timeout=None):
                self.joined = timeout == 1

            def is_alive(self):
                return False

        class ImmediatePool:
            def __init__(self, max_workers):
                self._processes = {0: FakeProcess()}
                self.shutdown_calls = []
                pools.append(self)

            def submit(self, _callable, payload):
                task = payload[0]
                future = concurrent.futures.Future()
                future.set_result(
                    ScanOutcome(
                        full_name=task.full_name,
                        head_sha=task.head_sha,
                        status="clean_reject",
                        result={},
                        seconds=0.01,
                        candidate_library_ids=(
                            task.candidate_library_ids
                        ),
                    )
                )
                return future

            def shutdown(self, **kwargs):
                self.shutdown_calls.append(kwargs)

        def fail_checkpoint(_outcome):
            raise RuntimeError("synthetic checkpoint budget failure")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            scanner_v2.concurrent.futures,
            "ProcessPoolExecutor",
            ImmediatePool,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "synthetic checkpoint budget failure"
            ):
                scan_many(
                    [ScanTask("public/example", "a" * 40, ())],
                    [],
                    Path(temporary) / "cache",
                    workers=1,
                    cache_target_bytes=10**6,
                    cache_hard_bytes=2 * 10**6,
                    on_result=fail_checkpoint,
                )
        self.assertTrue(all(process.terminated for process in processes))
        self.assertTrue(all(process.joined for process in processes))
        self.assertEqual(
            [pool.shutdown_calls for pool in pools],
            [[{"wait": False, "cancel_futures": True}]],
        )

    def test_alarm_delivery_during_disarm_cannot_override_worker_result(self):
        class FakeCache:
            last_network_fetch = False
            network_clone_count = 0
            network_fetch_count = 0
            network_materialized_bytes = 0

            def __init__(self, *_args, **_kwargs):
                pass

            @contextlib.contextmanager
            def checkout(
                self,
                _full_name,
                _head_sha,
                *,
                evidence_library_ids=(),
            ):
                self.last_lfs_materialized_paths = ()
                yield Path(temporary) / "checkout", "a" * 40

            def ensure_full_history_locked(self, _full_name):
                pass

            def entry_size(self, _full_name):
                return 1

        cancellation_calls = []

        def racing_setitimer(_which, seconds):
            if seconds == 0:
                cancellation_calls.append(seconds)
                if len(cancellation_calls) == 1:
                    raise scanner_v2._WorkerDeadline(
                        "deadline arrived during cancellation"
                    )

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            scanner_v2, "RepoCache", FakeCache
        ), mock.patch.object(
            scanner_v2.signal,
            "setitimer",
            side_effect=racing_setitimer,
        ), mock.patch.object(
            scanner_v2.scan,
            "analyze_repository",
            return_value={"repo": "public/race"},
        ), mock.patch.object(
            scanner_v2.scan,
            "_terminate_active_process_group",
        ):
            outcome = _worker(
                (
                    ScanTask(
                        "public/race",
                        "a" * 40,
                        (),
                        analysis_only=True,
                    ),
                    [],
                    Path(temporary) / "cache",
                    10**6,
                    2 * 10**6,
                    60,
                    "unused",
                    None,
                    Path(temporary) / "worker.active",
                    10**6,
                )
            )

        self.assertEqual(outcome.status, "match", outcome.error)
        self.assertEqual(len(cancellation_calls), 2)

    def test_scan_many_contains_worker_deadline_from_future_result(self):
        class DeadlinePool:
            def __init__(self, *_args, **_kwargs):
                self._processes = {}

            def submit(self, _callable, _payload):
                future = concurrent.futures.Future()
                future.set_exception(
                    scanner_v2._WorkerDeadline(
                        "repository wall deadline exhausted"
                    )
                )
                return future

            def shutdown(self, **_kwargs):
                pass

        seen = []
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            scanner_v2.concurrent.futures,
            "ProcessPoolExecutor",
            DeadlinePool,
        ):
            outcomes = scan_many(
                [ScanTask("public/deadline", "a" * 40, ("cublas",))],
                [],
                Path(temporary) / "cache",
                workers=1,
                repo_timeout=1,
                cache_target_bytes=10**6,
                cache_hard_bytes=2 * 10**6,
                on_result=seen.append,
            )

        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].status, "error")
        self.assertIn("deadline", outcomes[0].error)
        self.assertEqual("repository_timeout", outcomes[0].error_code)
        self.assertTrue(outcomes[0].error_retryable)
        self.assertEqual(seen, outcomes)

    def test_mature_probe_finalize_matches_legacy_full_scan_all_bands(self):
        scenarios = [
            (
                "cublasdx", "confirmed",
                {"src/use.cu": "#include <cublasdx.hpp>\n"},
            ),
            (
                "cublasdx", "bundled",
                {"third_party/copy.hpp": "cublasdx\n"},
            ),
            (
                "cublasdx", "targeted",
                {"README.md": "cublasdx planned\n"},
            ),
            (
                "dali", "confirmed",
                {"use.py": "import nvidia.dali as dali\n"},
            ),
            (
                "dali", "bundled",
                {"requirements.txt": "nvidia-dali-cuda120\n"},
            ),
            (
                "dali", "targeted",
                {"config.yaml": "nvidia-dali planned\n"},
            ),
            (
                "nvpl", "confirmed",
                {"use.c": "#include <nvpl_blas.h>\n"},
            ),
            (
                "nvpl", "bundled",
                {"CMakeLists.txt": "find_package(nvpl)\n"},
            ),
            (
                "nvpl", "bundled",
                {"requirements.txt": "nvpl-blas\n"},
            ),
            (
                "nvpl", "targeted",
                {"notes.weird": "nvpl_blas planned\n"},
            ),
            (
                "cuquantum", "confirmed",
                {"src/use.cu": "#include <custatevec.h>\n"},
            ),
        ]
        for library_id, expected_classification, files in scenarios:
            with self.subTest(
                library_id=library_id,
                classification=expected_classification,
                files=tuple(files),
            ), tempfile.TemporaryDirectory() as td:
                repo = Path(td)
                _git(repo, "init", "-q", "-b", "main")
                _git(repo, "config", "user.name", "REQ14 Test")
                _git(repo, "config", "user.email", "req14@example.invalid")
                for relative, body in files.items():
                    path = repo / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body)
                _git(repo, "add", ".")
                _git(repo, "commit", "-q", "-m", "fixture")
                library = next(
                    lib for lib in LIBRARIES if lib["id"] == library_id
                )
                legacy = scan_module.scan_repo(
                    "public/fixture",
                    [library],
                    lambda _message: None,
                    checkout=str(repo),
                    include_history=True,
                )
                inventory = triage_tree(
                    repo, [library], inventory_all=True
                )
                with scan_module.current_tree_inventory(
                    repo, inventory.current_text
                ):
                    probe = scan_module.scan_repo(
                        "public/fixture",
                        [library],
                        lambda _message: None,
                        checkout=str(repo),
                        include_history=False,
                    )
                    finalized = scan_module.finalize_classified_results(
                        str(repo), probe["libraries"], [library]
                    )
                self.assertEqual(
                    expected_classification,
                    legacy["libraries"][library_id]["classification"],
                )
                self.assertEqual(
                    {
                        key: value
                        for key, value in legacy["libraries"][
                            library_id
                        ].items()
                        if not str(key).startswith("_")
                    },
                    {
                        key: value
                        for key, value in finalized[library_id].items()
                        if not str(key).startswith("_")
                    },
                )

    def test_mature_cuda_wheel_family_matching_is_bounded(self):
        matcher = scan_module._declared_distribution_matches
        self.assertTrue(matcher(
            "nvidia-dali-cuda120",
            "nvidia-dali",
            allow_mature_cuda_suffixes=True,
        ))
        self.assertTrue(matcher(
            "custatevec-cu12",
            "custatevec-cu",
            allow_mature_cuda_suffixes=True,
        ))
        for declared, expected, allow_suffix in (
            ("not-nvidia-dali-cuda120", "nvidia-dali", True),
            ("nvidia-dali-cuda120-local", "nvidia-dali", True),
            ("custatevec-cu12-local", "custatevec-cu", True),
            ("custatevec-cu12", "custatevec-cu", False),
        ):
            with self.subTest(declared=declared, expected=expected):
                self.assertFalse(matcher(
                    declared,
                    expected,
                    allow_mature_cuda_suffixes=allow_suffix,
                ))

    def test_mature_worker_uses_one_classifier_and_whole_tree_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, remote, head = _fixture_remote(
                root,
                "public/whole-tree",
                {
                    "README.md": "Plans target cuBLASDx.\n",
                    "notes/integration.weird": "cublasdx planned\n",
                    "assets/large.bin": "\0" * 1_000_100,
                    "CITATION.cff": (
                        "cff-version: 1.2.0\n"
                        "title: Whole-tree fixture\n"
                    ),
                },
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            library = next(
                lib for lib in LIBRARIES if lib["id"] == "cublasdx"
            )
            original = scan_module.scan_repo
            registry = root / "cache" / "worker.active"
            with mock.patch.object(
                scan_module, "scan_repo", wraps=original
            ) as classifier:
                outcome = _worker(
                    (
                        ScanTask(
                            "public/whole-tree",
                            head,
                            ("cublasdx",),
                        ),
                        [library],
                        root / "cache",
                        10**9,
                        2 * 10**9,
                        60,
                        (
                            "file://"
                            + str(root / "remotes" / "{full_name}.git")
                        ),
                        None,
                        registry,
                        5 * 10**8,
                    )
                )
            self.assertEqual("match", outcome.status, outcome.error)
            self.assertEqual(1, classifier.call_count)
            self.assertEqual(
                "targeted",
                outcome.result["libraries"]["cublasdx"]["classification"],
            )
            self.assertEqual(
                {
                    "CITATION.cff": (
                        "cff-version: 1.2.0\n"
                        "title: Whole-tree fixture\n"
                    )
                },
                outcome.result["citation_cff"],
            )
            self.assertEqual(0, outcome.skipped_large_files)
            self.assertEqual(1, outcome.pruned_large_assets)
            self.assertEqual(
                {
                    "files_examined": outcome.files_examined,
                    "bytes_examined": outcome.bytes_examined,
                    "skipped_large_files": 0,
                    "pruned_large_assets": 1,
                },
                outcome.result["triage"],
            )

    @unittest.skipUnless(
        hasattr(os, "killpg") and hasattr(signal, "SIGSTOP"),
        "requires POSIX process groups",
    )
    def test_outer_deadline_kills_worker_git_group_and_descendant(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            pid_path = root / "fake-git-pids"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/bin/sh\n"
                "sleep 300 &\n"
                "child=$!\n"
                "printf '%s %s\\n' \"$$\" \"$child\""
                " > \"$REQ14_FAKE_GIT_PIDS\"\n"
                "wait \"$child\"\n"
            )
            fake_git.chmod(0o755)
            frozen_workers = []
            stop_watching = threading.Event()

            def freeze_worker():
                registry_root = root / "cache" / "process-groups"
                deadline = time.monotonic() + 5
                while (
                    not stop_watching.is_set()
                    and time.monotonic() < deadline
                ):
                    for registry in registry_root.glob("*.active"):
                        try:
                            worker_pid = int(
                                registry.read_text().split()[0]
                            )
                            os.kill(worker_pid, signal.SIGSTOP)
                        except (
                            FileNotFoundError,
                            IndexError,
                            ProcessLookupError,
                            ValueError,
                        ):
                            continue
                        frozen_workers.append(worker_pid)
                        return
                    time.sleep(0.01)

            watcher = threading.Thread(target=freeze_worker, daemon=True)
            watcher.start()
            environment = {
                "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
                "REQ14_FAKE_GIT_PIDS": str(pid_path),
            }
            started = time.monotonic()
            try:
                with mock.patch.dict(os.environ, environment):
                    outcomes = scan_many(
                        [
                            ScanTask(
                                "public/hanging",
                                "a" * 40,
                                ("cublas",),
                            )
                        ],
                        [],
                        root / "cache",
                        workers=1,
                        repo_timeout=60,
                        cache_target_bytes=10**9,
                        cache_hard_bytes=2 * 10**9,
                        run_deadline=time.monotonic() + 1.0,
                    )
            finally:
                stop_watching.set()
                watcher.join(timeout=2)
            self.assertEqual(outcomes, [])
            self.assertTrue(frozen_workers)
            self.assertLess(time.monotonic() - started, 5)
            git_pid, descendant_pid = (
                int(value) for value in pid_path.read_text().split()
            )
            ps_command = shutil.which("ps")
            self.assertIsNotNone(
                ps_command,
                "ps is required for process cleanup validation",
            )

            def active(pid):
                result = subprocess.run(
                    [ps_command, "-o", "stat=", "-p", str(pid)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                return bool(result.stdout.strip()) and not (
                    result.stdout.strip().startswith("Z")
                )

            reap_deadline = time.monotonic() + 2
            while (
                (active(git_pid) or active(descendant_pid))
                and time.monotonic() < reap_deadline
            ):
                time.sleep(0.02)
            self.assertFalse(active(git_pid), "Git process group leader survived")
            self.assertFalse(
                active(descendant_pid), "Git descendant survived cancellation"
            )

    def test_dali_python_syntax_rejects_oneflow_docstring_regression(self):
        """OneFlow commit 2c535132a85f added DALI guide URLs, not integration."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/oneflow-shaped",
                {
                    "python/setup.py": "from setuptools import setup\nsetup()\n",
                    "python/oneflow/nn/modules/dataset.py": (
                        '"""See https://docs.nvidia.com/deeplearning/dali/'
                        'user-guide/docs/index.html and example::\\n\\n'
                        '    import nvidia.dali\\n"""\\n'
                    ),
                },
            )
            dali = [lib for lib in LIBRARIES if lib["id"] == "dali"]
            outcomes = scan_many(
                [ScanTask("public/oneflow-shaped", head, ("dali",))],
                dali,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(root / "remotes" / "{full_name}.git"),
            )
            self.assertEqual(outcomes[0].status, "clean_reject")

    def test_dali_python_syntax_accepts_real_import_at_source_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/dali-real",
                {
                    "python/setup.py": "from setuptools import setup\nsetup()\n",
                    "python/project/loader.py": (
                        "import nvidia.dali as dali\n"
                        "pipeline = dali.pipeline.Pipeline()\n"
                    ),
                },
            )
            dali = [lib for lib in LIBRARIES if lib["id"] == "dali"]
            outcomes = scan_many(
                [ScanTask("public/dali-real", head, ("dali",))],
                dali,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(root / "remotes" / "{full_name}.git"),
            )
            self.assertEqual(outcomes[0].status, "match", outcomes[0].error)
            self.assertEqual(
                outcomes[0].result["libraries"]["dali"]["classification"],
                "confirmed",
            )

    def test_selective_lower_band_and_mature_classification_contracts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/mixed",
                {
                    "src/direct.cu": "#include <cublas_v2.h>\n",
                    "CMakeLists.txt": "# cufftdx planned backend\n",
                    "requirements.txt": "cudf-cu12\n",
                },
            )
            selected = [
                lib for lib in LIBRARIES
                if lib["id"] in {"cublas", "cudf", "cufftdx"}
            ]
            outcomes = scan_many(
                [ScanTask("public/mixed", head, ("cublas", "cudf", "cufftdx"))],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(root / "remotes" / "{full_name}.git"),
            )
            self.assertEqual(len(outcomes), 1)
            outcome = outcomes[0]
            self.assertEqual(outcome.status, "match", outcome.error)
            rows = outcome.result["libraries"]
            self.assertEqual(rows["cublas"]["classification"], "confirmed")
            self.assertEqual(rows["cufftdx"]["classification"], "targeted")
            self.assertEqual(rows["cudf"]["classification"], "bundled")

    def test_mature_header_prefix_collision_is_never_confirmed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/mature-collision",
                {"src/collision.cu": "#include <fakecufftdx.hpp>\n"},
            )
            mature = [lib for lib in LIBRARIES if lib["id"] == "cufftdx"]
            outcome = scan_many(
                [ScanTask("public/mature-collision", head, ("cufftdx",))],
                mature,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(root / "remotes" / "{full_name}.git"),
            )[0]
            if outcome.status == "match":
                self.assertNotEqual(
                    outcome.result["libraries"]["cufftdx"]["classification"],
                    "confirmed",
                )

    def test_rename_plus_edit_keeps_true_first_use_without_follow_sweep(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, _remote, initial_head = _fixture_remote(
                root,
                "public/renamed",
                {
                    "src/original.cu": (
                        "#include <cublas_v2.h>\n"
                        "int a = 1;\n"
                        "int b = 2;\n"
                        "int c = 3;\n"
                    )
                },
            )
            _git(source, "mv", "src/original.cu", "src/current.cu")
            with (source / "src/current.cu").open("a") as stream:
                stream.write("int edited_during_rename = 4;\n")
            _git(source, "add", ".")
            _git(source, "commit", "-q", "-m", "rename and edit")
            _git(source, "push", "-q", "origin", "main")
            current_head = _git(source, "rev-parse", "HEAD")
            library = next(
                lib for lib in LIBRARIES if lib["id"] == "cublas"
            )
            outcome = scan_many(
                [ScanTask("public/renamed", current_head, ("cublas",))],
                [library],
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )[0]
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertEqual(
                outcome.result["libraries"]["cublas"][
                    "first_integration_commit"
                ],
                initial_head[:12],
            )

    def test_root_commit_skips_impossible_rename_similarity_scan(self):
        commit = "a" * 40
        calls = []

        def fake_git(_dest, *args, **_kwargs):
            calls.append((args, _kwargs))
            if args == (
                "rev-list",
                "--parents",
                "-n",
                "1",
                commit,
            ):
                return commit + "\n"
            raise AssertionError(
                "root commit must not run diff-tree similarity detection"
            )

        with mock.patch.object(scan_module, "_git", side_effect=fake_git):
            self.assertEqual(
                {},
                scan_module._rename_predecessors(
                    "/fixture", commit, "50%"
                ),
            )
        self.assertEqual(len(calls), 1)

    def test_edited_rename_similarity_uses_bounded_history_timeout(self):
        commit = "b" * 40
        calls = []

        def fake_git(_dest, *args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == "rev-list":
                return commit + " " + ("c" * 40) + "\n"
            if args[0] == "diff-tree":
                return ""
            raise AssertionError(args)

        with mock.patch.object(scan_module, "_git", side_effect=fake_git):
            self.assertEqual(
                {},
                scan_module._rename_predecessors(
                    "/fixture", commit, "50%"
                ),
            )
        self.assertEqual(calls[1][1]["timeout"], 420)

    def test_first_use_batches_large_evidence_path_sets_without_semantic_loss(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            paths = []
            for index in range(200):
                relative = "src/use_%03d.cu" % index
                paths.append(relative)
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#include <cublas_v2.h>\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "integrate cuBLAS")
            first_commit = _git(repo, "rev-parse", "HEAD")

            scan_module.reset_git_subprocess_count()
            dated = scan_module._date_first_use(
                str(repo),
                "cublas_v2.h",
                paths,
                True,
                "cublas_v2\\.h",
            )
            branch = scan_module._dating_branch(
                "cublas_v2.h",
                paths,
                True,
                "cublas_v2\\.h",
            )
            boundary = scan_module._first_use_boundary(
                str(repo),
                dated,
                branch,
                scan_module._dating_plan_signature((branch,)),
            )
            subprocesses = scan_module.git_subprocess_count()

        self.assertEqual(first_commit, dated[1])
        self.assertEqual(first_commit, boundary["commit"])
        self.assertIn(boundary["evidence_path"], paths)
        self.assertLess(
            subprocesses,
            20,
            "path batching regressed to per-evidence-path Git work",
        )

    def test_unchanged_plan_reuses_validated_first_use_without_pickaxe(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            path = repo / "src/use.cu"
            path.parent.mkdir(parents=True)
            path.write_text("#include <cublas_v2.h>\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "integrate cuBLAS")
            first_commit = _git(repo, "rev-parse", "HEAD")
            library = next(
                lib
                for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "cublas"
            )
            initial = direct_result_from_files(
                repo, library, ("src/use.cu",)
            )
            boundaries = initial["_first_use_boundaries"]
            self.assertEqual(
                boundaries["primary"]["commit"], first_commit
            )
            (repo / "README.md").write_text("later change\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "later change")
            with mock.patch.object(
                scan_module,
                "_date_first_use",
                side_effect=AssertionError(
                    "validated reuse must skip full pickaxe dating"
                ),
            ):
                reused = direct_result_from_files(
                    repo,
                    library,
                    ("src/use.cu",),
                    prior_boundaries=boundaries,
                    require_reuse=True,
                )
            self.assertEqual(
                reused["first_integration_commit"],
                first_commit[:12],
            )
            self.assertEqual(
                reused["_first_use_boundaries"], boundaries
            )

    def test_force_push_invalidates_prior_boundary_and_falls_back_complete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, remote, old_head = _fixture_remote(
                root,
                "public/force-pushed",
                {"src/use.cu": "#include <cublas_v2.h>\n"},
            )
            _git(remote, "config", "uploadpack.allowFilter", "true")
            library = next(
                lib
                for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "cublas"
            )
            cache_root = root / "cache"
            template = (
                "file://"
                + str(root / "remotes" / "{full_name}.git")
            )
            initial = scan_many(
                [
                    ScanTask(
                        "public/force-pushed",
                        old_head,
                        ("cublas",),
                    )
                ],
                [library],
                cache_root,
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=template,
            )[0]
            boundaries = initial.result["libraries"]["cublas"][
                "_first_use_boundaries"
            ]

            _git(source, "checkout", "-q", "--orphan", "replacement")
            _git(source, "rm", "-q", "-r", "-f", ".")
            (source / "src").mkdir(parents=True, exist_ok=True)
            (source / "src/new.cu").write_text(
                "#include <cublas_v2.h>\n"
            )
            _git(source, "add", ".")
            _git(source, "commit", "-q", "-m", "replacement history")
            new_head = _git(source, "rev-parse", "HEAD")
            _git(source, "branch", "-M", "main")
            _git(source, "push", "-q", "--force", "origin", "main")

            outcome = scan_many(
                [
                    ScanTask(
                        "public/force-pushed",
                        new_head,
                        ("cublas",),
                        prior_first_use_boundaries=((
                            "cublas",
                            json.dumps(
                                boundaries,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        ),),
                    )
                ],
                [library],
                cache_root,
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=template,
            )[0]
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertEqual(
                outcome.result["libraries"]["cublas"][
                    "first_integration_commit"
                ],
                new_head[:12],
            )
            self.assertNotEqual(new_head, old_head)

    def test_path_plan_change_falls_back_and_does_not_undercount_history(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _git(repo, "init", "-q", "-b", "main")
            _git(repo, "config", "user.name", "REQ14 Test")
            _git(repo, "config", "user.email", "req14@example.invalid")
            old_path = repo / "src/older.cu"
            old_path.parent.mkdir(parents=True)
            old_path.write_text(
                "#include <cublas_v2.h>\n"
                + "".join(
                    "int old_%d = %d;\n" % (index, index)
                    for index in range(20)
                )
            )
            _git(repo, "add", ".")
            _git(
                repo,
                "commit",
                "-q",
                "--date=2020-01-01T00:00:00Z",
                "-m",
                "older integration",
            )
            older_commit = _git(repo, "rev-parse", "HEAD")
            _git(repo, "rm", "-q", "src/older.cu")
            current_path = repo / "src/current.cu"
            current_path.parent.mkdir(parents=True, exist_ok=True)
            current_path.write_text(
                "#include <cublas_v2.h>\n"
                + "".join(
                    "float current_%d = %d.0f;\n" % (index, index)
                    for index in range(20)
                )
            )
            _git(repo, "add", ".")
            _git(
                repo,
                "commit",
                "-q",
                "--date=2021-01-01T00:00:00Z",
                "-m",
                "current integration",
            )
            library = next(
                lib
                for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "cublas"
            )
            prior = direct_result_from_files(
                repo, library, ("src/current.cu",)
            )["_first_use_boundaries"]
            old_path.write_text(
                "#include <cublas_v2.h>\n"
                + "".join(
                    "int old_%d = %d;\n" % (index, index)
                    for index in range(20)
                )
            )
            _git(repo, "add", ".")
            _git(
                repo,
                "commit",
                "-q",
                "--date=2022-01-01T00:00:00Z",
                "-m",
                "restore older evidence path",
            )
            with self.assertRaises(
                scan_module.FirstUseReuseUnavailable
            ):
                direct_result_from_files(
                    repo,
                    library,
                    ("src/current.cu", "src/older.cu"),
                    prior_boundaries=prior,
                    require_reuse=True,
                )
            fallback = direct_result_from_files(
                repo,
                library,
                ("src/current.cu", "src/older.cu"),
                prior_boundaries=prior,
            )
            self.assertEqual(
                fallback["first_integration_commit"],
                older_commit[:12],
            )
            self.assertEqual(
                fallback["first_integration"], "2020-01-01"
            )

    def test_all_req14_direct_detectors_run_in_one_blob_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cpp_lines = []
            py_lines = []
            for lib in REQ14_DIRECT_LIBRARIES:
                if lib.get("language") == "python":
                    if lib["id"] == "warp":
                        py_lines.extend(("import warp as wp", "wp.init()"))
                    elif lib["id"] == "morpheus":
                        py_lines.append(
                            "from morpheus.pipeline import Pipeline"
                        )
                    else:
                        py_lines.append("import %s" % lib["import_namespace"])
                if lib.get("cpp_headers"):
                    cpp_lines.append("#include <%s>" % lib["cpp_headers"][0])
                elif lib.get("header_prefixes"):
                    cpp_lines.append(
                        "#include <%sexample.hpp>"
                        % lib["header_prefixes"][0]
                    )
            _source, _remote, head = _fixture_remote(
                root,
                "public/all-direct",
                {
                    "src/all.cu": "\n".join(cpp_lines) + "\n",
                    "src/all.py": "\n".join(py_lines) + "\n",
                },
            )
            outcomes = scan_many(
                [ScanTask(
                    "public/all-direct",
                    head,
                    tuple(lib["id"] for lib in REQ14_DIRECT_LIBRARIES),
                )],
                REQ14_DIRECT_LIBRARIES,
                root / "cache",
                workers=1,
                repo_timeout=120,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(root / "remotes" / "{full_name}.git"),
            )
            outcome = outcomes[0]
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertEqual(
                set(outcome.result["libraries"]),
                {lib["id"] for lib in REQ14_DIRECT_LIBRARIES},
            )
            self.assertTrue(all(
                row["classification"] == "confirmed"
                for row in outcome.result["libraries"].values()
            ))

    def test_reviewed_lower_bands_run_through_direct_lane(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, declared_head = _fixture_remote(
                root,
                "public/direct-lane-declared",
                {
                    "requirements.txt": (
                        "warp-lang==1.8.0\n"
                        "tensorrt==10.0.0\n"
                    ),
                },
            )
            _source, _remote, targeted_head = _fixture_remote(
                root,
                "public/direct-lane-targeted",
                {
                    "CMakeLists.txt": (
                        "target_link_libraries(app PRIVATE "
                        "CUDA::cublas nvinfer)\n"
                    ),
                },
            )
            _source, _remote, shadowed_head = _fixture_remote(
                root,
                "public/direct-lane-shadowed",
                {
                    "warp/__init__.py": "def kernel(function): return function\n",
                    "app.py": (
                        "import warp\n"
                        "@warp.kernel\n"
                        "def local_kernel():\n"
                        "    pass\n"
                    ),
                    "requirements.txt": "warp-lang==1.8.0\n",
                    "src/cublas.h": "#pragma once\n",
                    "src/use.cpp": '#include "cublas.h"\n',
                    "CMakeLists.txt": (
                        "target_link_libraries(app PRIVATE CUDA::cublas)\n"
                    ),
                },
            )
            ids = {"warp", "tensorrt", "cublas"}
            selected = [
                library
                for library in REQ14_DIRECT_LIBRARIES
                if library["id"] in ids
            ]
            outcomes = scan_many(
                [
                    ScanTask(
                        "public/direct-lane-declared",
                        declared_head,
                        ("warp", "tensorrt"),
                    ),
                    ScanTask(
                        "public/direct-lane-targeted",
                        targeted_head,
                        ("cublas", "tensorrt"),
                    ),
                    ScanTask(
                        "public/direct-lane-shadowed",
                        shadowed_head,
                        ("warp", "cublas"),
                    ),
                ],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )
            by_name = {outcome.full_name: outcome for outcome in outcomes}
            declared = by_name["public/direct-lane-declared"]
            self.assertEqual("match", declared.status, declared.error)
            self.assertEqual(
                {"warp": "bundled", "tensorrt": "bundled"},
                {
                    library_id: row["classification"]
                    for library_id, row in declared.result[
                        "libraries"
                    ].items()
                },
            )
            targeted = by_name["public/direct-lane-targeted"]
            self.assertEqual("match", targeted.status, targeted.error)
            self.assertEqual(
                {"cublas": "targeted", "tensorrt": "targeted"},
                {
                    library_id: row["classification"]
                    for library_id, row in targeted.result[
                        "libraries"
                    ].items()
                },
            )
            shadowed = by_name["public/direct-lane-shadowed"]
            self.assertEqual("match", shadowed.status, shadowed.error)
            self.assertEqual(
                {"warp": "bundled", "cublas": "targeted"},
                {
                    library_id: row["classification"]
                    for library_id, row in shadowed.result[
                        "libraries"
                    ].items()
                },
            )

    def test_prefix_header_libraries_confirm_realistic_includes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/prefix-headers",
                {
                    "src/real.cu": (
                        "#include <cutlass/cutlass.h>\n"
                        "#include <thrust/device_vector.h>\n"
                        "#include <cub/cub.cuh>\n"
                        "#include <nvcomp/lz4.hpp>\n"
                    )
                },
            )
            ids = {"cutlass", "thrust", "cub", "nvcomp"}
            selected = [
                lib for lib in REQ14_DIRECT_LIBRARIES if lib["id"] in ids
            ]
            outcome = scan_many(
                [ScanTask("public/prefix-headers", head, tuple(sorted(ids)))],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(root / "remotes" / "{full_name}.git"),
            )[0]
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertEqual(set(outcome.result["libraries"]), ids)

    def test_prefix_header_library_copy_is_not_direct_integration(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/vendor-copy",
                {
                    "misc/nvcomp/README.md": "# What is nvCOMP?\n",
                    "misc/nvcomp/CMakeLists.txt": "project(nvcomp)\n",
                    "misc/nvcomp/src/CMakeLists.txt": (
                        "add_library(nvcomp)\n"
                    ),
                    "misc/nvcomp/include/nvcomp.h": (
                        "int nvcompBatchedLZ4CompressAsync(void);\n"
                    ),
                    "misc/nvcomp/include/nvcomp.hpp": (
                        "#include <nvcomp.h>\n"
                    ),
                    "misc/nvcomp/include/nvcomp/lz4.hpp": (
                        "#include <nvcomp.h>\n"
                    ),
                    "misc/nvcomp/examples/use.cu": (
                        "#include <nvcomp/lz4.hpp>\n"
                        "nvcompBatchedLZ4CompressAsync();\n"
                    ),
                },
            )
            selected = [
                lib for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "nvcomp"
            ]
            outcome = scan_many(
                [ScanTask("public/vendor-copy", head, ("nvcomp",))],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )[0]
            self.assertEqual(
                outcome.status, "clean_reject", outcome.error
            )

    def test_nested_libbsc_copy_is_not_cub_or_thrust_integration(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            copied_root = "bwt/libbsc"
            _source, _remote, head = _fixture_remote(
                root,
                "public/copied-libbsc",
                {
                    copied_root + "/AUTHORS": "libbsc authors\n",
                    copied_root + "/CMakeLists.txt": (
                        "add_library(libbsc)\n"
                    ),
                    copied_root + "/LICENSE": "license\n",
                    copied_root + "/README": "libbsc library\n",
                    copied_root + "/VERSION": "3.0\n",
                    copied_root + "/libbsc/libbsc.h": (
                        "int bsc_init(void);\n"
                    ),
                    copied_root
                    + "/libbsc/bwt/libcubwt/libcubwt.cu": (
                        "#include <cub/cub.cuh>\n"
                        "#include <thrust/device_vector.h>\n"
                    ),
                },
            )
            ids = {"cub", "thrust"}
            selected = [
                lib for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] in ids
            ]
            outcome = scan_many(
                [
                    ScanTask(
                        "public/copied-libbsc",
                        head,
                        tuple(sorted(ids)),
                    )
                ],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )[0]
            self.assertEqual(
                outcome.status, "clean_reject", outcome.error
            )

    def test_cutensor_mg_header_is_direct_integration(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _source, _remote, head = _fixture_remote(
                root,
                "public/cutensor-mg",
                {"src/use.cu": "#include <cutensorMg.h>\n"},
            )
            selected = [
                lib for lib in REQ14_DIRECT_LIBRARIES
                if lib["id"] == "cutensor"
            ]
            outcome = scan_many(
                [ScanTask("public/cutensor-mg", head, ("cutensor",))],
                selected,
                root / "cache",
                workers=1,
                repo_timeout=60,
                cache_target_bytes=10**9,
                cache_hard_bytes=2 * 10**9,
                remote_template=str(
                    root / "remotes" / "{full_name}.git"
                ),
            )[0]
            self.assertEqual(outcome.status, "match", outcome.error)
            self.assertEqual(
                outcome.result["libraries"]["cutensor"][
                    "classification"
                ],
                "confirmed",
            )


if __name__ == "__main__":
    unittest.main()
