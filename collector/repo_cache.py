"""Bounded persistent Git repository cache for the Mac-local V2 collector."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import config
from .evidence_content import LFSPointer, parse_lfs_pointer
from .scan import _git_auth_env, _run_command, _run_command_bytes
from .triage import (
    MAX_OWN_SOURCE_BYTES,
    MAX_SOURCE_BYTES,
    _eligible,
    _embedded_project_roots,
    _inside_embedded_project,
    _own_source,
    lfs_evidence_path_relevant,
)


class CacheError(RuntimeError):
    pass


# A non-cone sparse worktree materializes every surface that can contribute to
# direct, bundled, targeted, build, dependency, CFF, or repository-level
# evidence, while avoiding unrelated binary assets and generated archives.
# History commands still operate against the bare object database.
_SPARSE_PATTERNS = tuple(sorted({
    *("*." + extension for extension in (
        set(config.SOURCE_EXTS)
        | set(config.PY_SOURCE_EXTS)
        | set(config.TARGETED_EXTS)
        | {"c", "pyi", "yaml", "yml", "cmake", "mk", "bazel", "bzl", "txt"}
    )),
    *config.PY_DEP_PATHSPECS,
    *config.PY_DEP_FILENAMES,
    *config.TARGETED_FILENAMES,
    "CITATION.cff",
    "CITATION.CFF",
    "Citation.cff",
    "citation.cff",
    "BUILD",
    "BUILD.bazel",
    "WORKSPACE",
    "WORKSPACE.bazel",
    "meson.build",
    "meson.options",
}))
_CURRENT_TREE_BLOB_POLICY = "blob-limit-%d+sparse-v1" % MAX_SOURCE_BYTES
_MIN_GROWTH_RESERVATION = 64 * 1024**2
_POLICY_SIZE_BATCH_OBJECTS = 10_000
_CURRENT_TREE_FETCH_BATCH_OBJECTS = 1_000
_HISTORY_PATH_BATCH = 128
# A mature repository can have tens of thousands of small historical versions
# across its positive evidence paths.  A few hundred OIDs per fetch turns those
# into hundreds of network round trips (and one promisor pack per request).
# Ten thousand SHA-1 lines are still only about 400 KiB of bounded stdin.
_HISTORY_FETCH_BATCH_OBJECTS = 10_000
_MAX_LFS_OBJECTS_PER_REPOSITORY = 64
_MAX_LFS_OBJECT_BYTES = MAX_OWN_SOURCE_BYTES
_MAX_LFS_MATERIALIZED_BYTES = 512 * 1024**2
_UNSUPPORTED_LFS_PATH_RE = re.compile(r"[\r\n,*?\[\\]")
_RETENTION_PRIORITY_RANK = {
    # Cold negative caches are cheapest to recreate and have a durable verdict
    # in SQLite, so they leave before any history-bearing positive.
    "cold_clean_reject": 0,
    "clean_reject": 1,
    "error": 1,
    "unclassified": 2,
    "positive_history": 3,
}
_HISTORY_DEEPEN_STEPS = (
    32,
    128,
    512,
    2_048,
    8_192,
    32_768,
    131_072,
    524_288,
    # Explicit maximum-depth correctness fallback. This remains a bounded
    # fetch and avoids the old unconditional ``--unshallow`` operation.
    2_147_483_647,
)


@dataclass(frozen=True)
class HistoryAvailability:
    complete: bool
    reachable_commits: tuple[str, ...]
    deepen_fetches: int


def _run(command, timeout, cwd=None):
    try:
        effective = list(command)
        if cwd is not None:
            effective = ["git", "-C", str(cwd), *effective[1:]]
        result = _run_command(effective, timeout, env=_git_auth_env())
    except (TimeoutError, RuntimeError) as exc:
        # scan._run_command raises its bounded process-group failure as a
        # RuntimeError subclass. Normalize it so checkout cleanup and workers
        # take the cache-error path consistently.
        raise CacheError("%s failed: %s" % (command[0], str(exc)[:400])) from exc
    if result.returncode:
        detail = (result.stderr or result.stdout or "exit %d" % result.returncode).strip()
        raise CacheError("%s: %s" % (" ".join(command[:5]), detail[:400]))
    return result.stdout


def _tree_bytes(path):
    total = 0
    for base, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(base) / name).stat().st_size
            except FileNotFoundError:
                continue
    return total


def _write_json_atomic(path, payload):
    temporary = path.with_name(".%s.tmp-%d" % (path.name, os.getpid()))
    with temporary.open("w") as stream:
        stream.write(json.dumps(payload, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class RepoCache:
    """Treeless bare clones with per-repository locks and LRU eviction."""

    def __init__(self, root, target_bytes=200 * 1024**3,
                 hard_bytes=250 * 1024**3, git_timeout=300,
                 remote_template="https://github.com/{full_name}.git",
                 deadline_monotonic=None, reservation_bytes=0):
        self.root = Path(root).resolve()
        if self.root == Path("/") or self.root == Path.home() or len(self.root.parts) < 3:
            raise ValueError("refusing unsafe cache root: %s" % self.root)
        self.repos = self.root / "repos"
        self.locks = self.root / "locks"
        self.worktrees = self.root / "worktrees"
        self.target_bytes = int(target_bytes)
        self.hard_bytes = int(hard_bytes)
        self.git_timeout = int(git_timeout)
        self.remote_template = remote_template
        self.deadline_monotonic = (
            None
            if deadline_monotonic is None
            else float(deadline_monotonic)
        )
        self.reservation_bytes = max(0, int(reservation_bytes))
        self.last_network_fetch = False
        # Per-instance network accounting is intentionally monotonic. Scanner
        # workers create one cache instance per repository task, so these
        # counters describe the exact clone/fetch work performed for the
        # outcome instead of inferring network use from cache-hit status.
        self.network_clone_count = 0
        self.network_fetch_count = 0
        self.network_materialized_bytes = 0
        self.last_lfs_materialized_paths = ()
        self.last_lfs_materialization = ()
        self.accounting_lock_path = self.root / "cache-accounting.lock"
        self.usage_path = self.root / "cache-usage.json"
        if not (0 < self.target_bytes <= self.hard_bytes):
            raise ValueError("cache target must be positive and <= hard limit")
        for path in (self.repos, self.locks, self.worktrees):
            path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def key(full_name):
        return hashlib.sha256(full_name.lower().encode("utf-8")).hexdigest()

    def repo_path(self, full_name):
        return self.repos / (self.key(full_name) + ".git")

    def metadata_path(self, full_name):
        return self.repos / (self.key(full_name) + ".json")

    def _remaining_timeout(self, maximum):
        maximum = float(maximum)
        if self.deadline_monotonic is None:
            return maximum
        remaining = self.deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise CacheError("repository wall deadline is exhausted")
        return max(0.001, min(maximum, remaining))

    @contextlib.contextmanager
    def _accounting_lock(self):
        with self.accounting_lock_path.open("a+") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @contextlib.contextmanager
    def lock(self, full_name):
        path = self.locks / (self.key(full_name) + ".lock")
        with path.open("a+") as handle:
            if self.deadline_monotonic is None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            else:
                while True:
                    try:
                        fcntl.flock(
                            handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                        )
                        break
                    except BlockingIOError:
                        self._remaining_timeout(0.05)
                        time.sleep(
                            min(0.05, self._remaining_timeout(0.05))
                        )
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @contextlib.contextmanager
    def try_lock(self, full_name):
        """Yield whether an exclusive repo lock was acquired without waiting."""
        path = self.locks / (self.key(full_name) + ".lock")
        with path.open("a+") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _git_dir(self, full_name, *args, timeout=None):
        is_fetch = "fetch" in args
        repo = self.repo_path(full_name)
        before = _tree_bytes(repo) if is_fetch and repo.exists() else 0
        effective_timeout = self._remaining_timeout(
            timeout or self.git_timeout
        )
        if is_fetch:
            self.network_fetch_count += 1
        try:
            return _run(
                ["git", "--git-dir", str(self.repo_path(full_name)),
                 "-c", "core.commitGraph=false",
                 "-c", "maintenance.auto=false"] + list(args),
                effective_timeout,
            )
        finally:
            if is_fetch:
                self.network_materialized_bytes += max(
                    0, _tree_bytes(repo) - before
                )

    def _git_dir_bytes(
        self,
        full_name,
        *args,
        input_bytes=b"",
        timeout=None,
        no_lazy=False,
    ):
        is_fetch = "fetch" in args
        repo = self.repo_path(full_name)
        before = _tree_bytes(repo) if is_fetch and repo.exists() else 0
        env = _git_auth_env()
        if no_lazy:
            env["GIT_NO_LAZY_FETCH"] = "1"
        command = [
            "git",
            "--git-dir",
            str(self.repo_path(full_name)),
            "-c",
            "core.commitGraph=false",
            "-c",
            "maintenance.auto=false",
            *args,
        ]
        effective_timeout = self._remaining_timeout(
            timeout or self.git_timeout
        )
        if is_fetch:
            self.network_fetch_count += 1
        try:
            try:
                result = _run_command_bytes(
                    command,
                    effective_timeout,
                    input_bytes=input_bytes,
                    env=env,
                )
            except (TimeoutError, RuntimeError) as exc:
                raise CacheError(
                    "git %s failed: %s" % (
                        str(args[0]) if args else "command",
                        str(exc)[:400],
                    )
                ) from exc
            if result.returncode:
                detail = (
                    result.stderr or result.stdout
                    or ("exit %d" % result.returncode).encode("ascii")
                ).decode("utf-8", errors="replace").strip()
                raise CacheError(
                    "git %s: %s" % (
                        str(args[0]) if args else "command",
                        detail[:400],
                    )
                )
            return result.stdout
        finally:
            if is_fetch:
                self.network_materialized_bytes += max(
                    0, _tree_bytes(repo) - before
                )

    def _read_metadata(self, full_name):
        path = self.metadata_path(full_name)
        try:
            payload = json.loads(path.read_text())
            return payload if isinstance(payload, dict) else {}
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return {}

    @staticmethod
    def _accounted_bytes(metadata):
        return (
            max(0, int(metadata.get("bytes", 0) or 0))
            + max(
                0,
                int(metadata.get("reserved_growth_bytes", 0) or 0),
            )
        )

    def _rebuild_usage_locked(self):
        total = 0
        for repo in self.repos.glob("*.git"):
            meta = self.repos / (repo.name[:-4] + ".json")
            try:
                payload = json.loads(meta.read_text()) if meta.exists() else {}
                size = int(payload.get("bytes", -1))
            except (OSError, ValueError, TypeError):
                payload, size = {}, -1
            if size < 0:
                size = _tree_bytes(repo)
            if payload:
                payload["bytes"] = size
                payload.pop("reserved", None)
                payload.pop("reserved_growth_bytes", None)
                _write_json_atomic(meta, payload)
            total += size
        _write_json_atomic(self.usage_path, {"total_bytes": total})
        return total

    def reconcile_accounting(self):
        """Reconcile cache bytes and remove ownerless partial repositories.

        This intentionally performs the only all-cache walk once in the parent
        coordinator before workers start. Normal worker accounting remains
        per-repository and O(1) in the number of cached repositories.
        """
        with self._accounting_lock():
            total = 0
            for repo in sorted(self.repos.glob("*.git")):
                key = repo.name[:-4]
                meta = self.repos / (key + ".json")
                try:
                    payload = json.loads(meta.read_text())
                except (FileNotFoundError, OSError, TypeError, ValueError):
                    payload = {}
                full_name = payload.get("full_name")
                if (
                    not isinstance(full_name, str)
                    or not full_name
                    or self.key(full_name) != key
                ):
                    shutil.rmtree(repo)
                    if repo.exists():
                        raise CacheError(
                            "could not remove ownerless cache entry: %s" % repo
                        )
                    meta.unlink(missing_ok=True)
                    continue
                size = _tree_bytes(repo)
                payload["bytes"] = size
                payload.pop("reserved", None)
                payload.pop("reserved_growth_bytes", None)
                payload.setdefault("last_access", repo.stat().st_mtime)
                _write_json_atomic(meta, payload)
                total += size
            for meta in self.repos.glob("*.json"):
                repo = self.repos / (meta.stem + ".git")
                if not repo.exists():
                    meta.unlink(missing_ok=True)
            self._write_usage_locked(total)
        self.enforce_budget()
        return total

    def _usage_locked(self):
        try:
            payload = json.loads(self.usage_path.read_text())
            total = int(payload["total_bytes"])
            if total < 0:
                raise ValueError
            return total
        except (FileNotFoundError, OSError, KeyError, ValueError, TypeError):
            return self._rebuild_usage_locked()

    def _write_usage_locked(self, total):
        _write_json_atomic(
            self.usage_path,
            {"total_bytes": max(0, int(total))},
        )

    def _record_metadata(
        self,
        full_name,
        *,
        head_sha,
        size,
        accessed=None,
        current_tree_head=None,
    ):
        accessed = time.time() if accessed is None else float(accessed)
        path = self.metadata_path(full_name)
        with self._accounting_lock():
            usage_existed = self.usage_path.exists()
            metadata_existed = path.exists()
            total = self._usage_locked()
            old = self._read_metadata(full_name)
            old_size = (
                self._accounted_bytes(old)
                if "bytes" in old or "reserved_growth_bytes" in old
                else (
                    _tree_bytes(self.repo_path(full_name))
                    if not usage_existed and self.repo_path(full_name).exists()
                    else 0
                )
            )
            if not metadata_existed and usage_existed:
                old_size = 0
            payload = {
                "full_name": full_name,
                "head_sha": head_sha,
                "last_access": accessed,
                "bytes": max(0, int(size)),
            }
            current_tree_blob_head = (
                current_tree_head
                if current_tree_head is not None
                else old.get("current_tree_blob_head")
            )
            if isinstance(current_tree_blob_head, str):
                payload["current_tree_blob_head"] = current_tree_blob_head
            current_tree_blob_policy = (
                _CURRENT_TREE_BLOB_POLICY
                if current_tree_head is not None
                else old.get("current_tree_blob_policy")
            )
            if isinstance(current_tree_blob_policy, str):
                payload["current_tree_blob_policy"] = (
                    current_tree_blob_policy
                )
            for field in (
                "retention_priority",
                "last_verdict_at",
                "verdict_cache_hit",
                "lfs_materialization",
            ):
                if field in old:
                    payload[field] = old[field]
            proposed = total - old_size + payload["bytes"]
            removed = []
            if proposed > self.hard_bytes:
                proposed, removed = self._evict_locked(
                    proposed,
                    excluded={self.key(full_name)},
                    goal=self.hard_bytes,
                )
            if proposed > self.hard_bytes:
                repo = self.repo_path(full_name)
                shutil.rmtree(repo, ignore_errors=True)
                if repo.exists():
                    # Keep accounting truthful if the filesystem refused the
                    # removal; startup reconciliation can retry safely.
                    _write_json_atomic(path, payload)
                    self._write_usage_locked(proposed)
                else:
                    path.unlink(missing_ok=True)
                    proposed = max(0, proposed - payload["bytes"])
                    self._write_usage_locked(proposed)
                raise CacheError(
                    "cache entry exceeds hard limit after safe eviction"
                )
            _write_json_atomic(path, payload)
            self._write_usage_locked(proposed)
        return removed

    def entry_size(self, full_name):
        return max(0, int(self._read_metadata(full_name).get("bytes", 0) or 0))

    def record_outcome_priority(
        self, full_name, *, status, cache_hit, recorded_at=None
    ):
        """Persist coordinator-known cache value without touching verdict data.

        SQLite remains the durable result store. This metadata controls only
        which reconstructible Git object cache leaves first under disk
        pressure.
        """
        if status == "match":
            priority = "positive_history"
        elif status == "clean_reject":
            priority = (
                "clean_reject" if cache_hit else "cold_clean_reject"
            )
        elif status == "error":
            priority = "error"
        else:
            priority = "unclassified"
        path = self.metadata_path(full_name)
        with self._accounting_lock():
            if not self.repo_path(full_name).exists():
                return False
            metadata = self._read_metadata(full_name)
            if not metadata:
                return False
            metadata["retention_priority"] = priority
            metadata["last_verdict_at"] = (
                time.time() if recorded_at is None else float(recorded_at)
            )
            metadata["verdict_cache_hit"] = bool(cache_hit)
            _write_json_atomic(path, metadata)
        return True

    def _begin_growth_reservation(self, full_name):
        """Reserve cache headroom before an existing entry can fetch objects."""
        repo = self.repo_path(full_name)
        current_size = _tree_bytes(repo) if repo.exists() else 0
        expected_growth = max(
            0, self.reservation_bytes - current_size
        )
        minimum_growth = min(
            _MIN_GROWTH_RESERVATION,
            max(0, self.hard_bytes - current_size),
        )
        reserve = max(expected_growth, minimum_growth)
        path = self.metadata_path(full_name)
        with self._accounting_lock():
            total = self._usage_locked()
            metadata = self._read_metadata(full_name)
            old_accounted = self._accounted_bytes(metadata)
            if not metadata and repo.exists() and not self.usage_path.exists():
                old_accounted = current_size
            metadata.update({
                "full_name": full_name,
                "bytes": current_size,
                "last_access": time.time(),
            })
            metadata.pop("reserved", None)
            metadata["reserved_growth_bytes"] = reserve
            proposed = total - old_accounted + current_size + reserve
            if proposed > self.hard_bytes:
                proposed, _removed = self._evict_locked(
                    proposed,
                    excluded={self.key(full_name)},
                    goal=self.hard_bytes,
                )
            if proposed > self.hard_bytes:
                metadata.pop("reserved_growth_bytes", None)
                actual_total = max(0, proposed - reserve)
                if actual_total > self.hard_bytes:
                    shutil.rmtree(repo, ignore_errors=True)
                    if repo.exists():
                        _write_json_atomic(path, metadata)
                    else:
                        path.unlink(missing_ok=True)
                        actual_total = max(
                            0, actual_total - current_size
                        )
                else:
                    _write_json_atomic(path, metadata)
                self._write_usage_locked(actual_total)
                raise CacheError(
                    "cache growth reservation would exceed hard limit"
                )
            _write_json_atomic(path, metadata)
            self._write_usage_locked(proposed)

    @contextlib.contextmanager
    def _growth_reservation_locked(self, full_name):
        """Reserve, then replace the reservation with measured cache bytes."""
        self._begin_growth_reservation(full_name)
        try:
            yield
        finally:
            repo = self.repo_path(full_name)
            metadata = self._read_metadata(full_name)
            if repo.exists():
                self._record_metadata(
                    full_name,
                    head_sha=metadata.get("head_sha"),
                    size=_tree_bytes(repo),
                )
            else:
                with self._accounting_lock():
                    total = self._usage_locked()
                    old = self._read_metadata(full_name)
                    self.metadata_path(full_name).unlink(missing_ok=True)
                    self._write_usage_locked(
                        max(0, total - self._accounted_bytes(old))
                    )

    def ensure(self, full_name, head_sha=None):
        """Create/fetch a cache and return the resolved commit SHA."""
        repo = self.repo_path(full_name)
        self.last_network_fetch = False
        with self.lock(full_name):
            if not repo.exists():
                reserve = max(self.reservation_bytes, 64 * 1024**2)
                with self._accounting_lock():
                    total = self._usage_locked()
                    proposed = total + reserve
                    if proposed > self.hard_bytes:
                        proposed, _removed = self._evict_locked(
                            proposed,
                            excluded={self.key(full_name)},
                            goal=self.hard_bytes,
                        )
                    if proposed > self.hard_bytes:
                        self._write_usage_locked(
                            max(0, proposed - reserve)
                        )
                        raise CacheError(
                            "cache reservation would exceed hard limit"
                        )
                    _write_json_atomic(
                        self.metadata_path(full_name),
                        {
                            "full_name": full_name,
                            "head_sha": None,
                            "last_access": time.time(),
                            "bytes": 0,
                            "reserved_growth_bytes": reserve,
                        },
                    )
                    self._write_usage_locked(proposed)
                tmp = repo.with_name(repo.name + ".creating-%d" % os.getpid())
                if tmp.exists():
                    shutil.rmtree(tmp)
                clone_timeout = self._remaining_timeout(self.git_timeout)
                self.network_clone_count += 1
                try:
                    _run([
                        "git", "clone", "--bare",
                        (
                            "--filter=blob:none"
                            if head_sha
                            else "--filter=tree:0"
                        ),
                        "--quiet",
                        "--no-tags", "--single-branch", "--depth=1",
                        "-c", "core.commitGraph=false",
                        "-c", "maintenance.auto=false",
                        self.remote_template.format(full_name=full_name),
                        str(tmp),
                    ], clone_timeout)
                    os.replace(tmp, repo)
                    self.last_network_fetch = True
                except BaseException:
                    with self._accounting_lock():
                        total = self._usage_locked()
                        reserved = self._read_metadata(full_name)
                        amount = self._accounted_bytes(reserved)
                        self.metadata_path(full_name).unlink(missing_ok=True)
                        self._write_usage_locked(max(0, total - amount))
                    raise
                finally:
                    materialized = repo if repo.exists() else tmp
                    self.network_materialized_bytes += _tree_bytes(
                        materialized
                    )
                    if tmp.exists():
                        shutil.rmtree(tmp, ignore_errors=True)
            if head_sha:
                present = True
                try:
                    self._git_dir(
                        full_name,
                        "cat-file",
                        "-e",
                        "%s^{commit}" % head_sha,
                        timeout=30,
                    )
                except CacheError:
                    present = False
                if not present:
                    shallow = self._git_dir(
                        full_name,
                        "rev-parse",
                        "--is-shallow-repository",
                        timeout=30,
                    ).strip().casefold()
                    depth = (
                        ["--depth=1", "--filter=blob:none"]
                        if shallow == "true"
                        else ["--filter=blob:none"]
                    )
                    with self._growth_reservation_locked(full_name):
                        self._git_dir(
                            full_name, "fetch", "--quiet", "--no-tags", *depth,
                            "origin", head_sha, timeout=self.git_timeout,
                        )
                    self.last_network_fetch = True
                resolved = self._git_dir(
                    full_name, "rev-parse", "--verify", "%s^{commit}" % head_sha,
                    timeout=30,
                ).strip()
            else:
                with self._growth_reservation_locked(full_name):
                    self._git_dir(
                        full_name, "fetch", "--quiet", "--no-tags", "origin",
                        timeout=self.git_timeout,
                    )
                self.last_network_fetch = True
                resolved = self._git_dir(
                    full_name, "rev-parse", "--verify", "FETCH_HEAD^{commit}",
                    timeout=30,
                ).strip()
            os.utime(repo, None)
            self._record_metadata(
                full_name,
                head_sha=resolved,
                size=_tree_bytes(repo),
            )
        return resolved

    def ensure_current_tree_blobs_locked(self, full_name, head_sha):
        """Fetch the selected HEAD's blobs in one pack for mature detectors.

        Mature confirmed/bundled/targeted classification intentionally searches
        README and unusual tracked text in addition to the sparse direct
        surface. Leaving those blobs promised causes ``git grep`` to issue
        hundreds or thousands of serial lazy fetches. A depth-one filtered
        refetch materializes every ordinary-size current blob in one pack;
        already-materialized large own-source files remain available, while
        still-promised large assets are removed from the ephemeral scan index
        by :meth:`prune_missing_current_blobs_locked`.

        The caller holds the repository lock.  A content marker makes warm
        scans at the same HEAD network-free.
        """
        head_sha = str(head_sha or "").strip()
        if not head_sha:
            raise CacheError("current-tree blob hydration requires a resolved HEAD")
        metadata = self._read_metadata(full_name)
        if (
            metadata.get("current_tree_blob_head") == head_sha
            and metadata.get("current_tree_blob_policy")
            == _CURRENT_TREE_BLOB_POLICY
        ):
            return False
        shallow = self._git_dir(
            full_name,
            "rev-parse",
            "--is-shallow-repository",
            timeout=30,
        ).strip().casefold()
        if shallow != "true":
            # A cache created before this marker may already contain full
            # history.  Detect the common complete-current-tree case without
            # allowing Git's promisor remote to lazily fetch anything.  Never
            # refetch every historical blob merely to upgrade old metadata.
            env = _git_auth_env()
            env["GIT_NO_LAZY_FETCH"] = "1"
            command = [
                "git",
                "--git-dir",
                str(self.repo_path(full_name)),
                "-c",
                "core.commitGraph=false",
                "-c",
                "maintenance.auto=false",
                "rev-list",
                "--objects",
                "--missing=print",
                "--max-count=1",
                head_sha,
            ]
            result = _run_command(
                command,
                self._remaining_timeout(30),
                env=env,
            )
            if result.returncode:
                raise CacheError(
                    "could not inspect current-tree object completeness"
                )
            if not any(
                line.startswith("?") for line in result.stdout.splitlines()
            ):
                self._record_metadata(
                    full_name,
                    head_sha=head_sha,
                    size=_tree_bytes(self.repo_path(full_name)),
                    current_tree_head=head_sha,
                )
                return False
        with self._growth_reservation_locked(full_name):
            self._git_dir(
                full_name,
                "fetch",
                "--quiet",
                "--no-tags",
                "--refetch",
                "--depth=1",
                "--filter=blob:limit=%d" % (MAX_SOURCE_BYTES + 1),
                "origin",
                head_sha,
                timeout=self.git_timeout,
            )
            self.last_network_fetch = True
        self._record_metadata(
            full_name,
            head_sha=head_sha,
            size=_tree_bytes(self.repo_path(full_name)),
            current_tree_head=head_sha,
        )
        return True

    def prepare_bare_current_tree_locked(self, full_name, head_sha):
        """Return the pinned tree after selectively hydrating triage blobs.

        Direct-only triage needs tracked path names plus the contents of files
        that can contribute scanner evidence.  It does not need an index or a
        worktree.  Enumerate the resolved commit without opening blobs, then
        explicitly fetch only eligible scanner files and ``.gitattributes``
        control files.  The latter are required to reproduce checkout EOL
        semantics from the bare object database.

        Every availability check disables promisor lazy fetching.  Explicit
        fetches retain the existing deadline, growth-reservation, and hard
        cache-limit boundaries; a missing object after hydration is an
        incomplete scan, never a clean reject.

        The caller holds the per-repository lock.
        """
        head_sha = str(head_sha or "").strip()
        if not head_sha:
            raise CacheError("bare current-tree triage requires a resolved HEAD")
        listing = self._git_dir_bytes(
            full_name,
            "-c",
            "core.quotePath=false",
            "ls-tree",
            "-r",
            "-z",
            "--format=%(objectmode)%x09%(objecttype)%x09"
            "%(objectname)%x09%(path)",
            head_sha,
            timeout=self.git_timeout,
            no_lazy=True,
        )
        entries = []
        for record in listing.split(b"\0"):
            if not record:
                continue
            fields = record.split(b"\t", 3)
            if len(fields) != 4:
                raise CacheError("malformed bare current-tree entry")
            try:
                mode = fields[0].decode("ascii", errors="strict")
                object_type = fields[1].decode("ascii", errors="strict")
                object_id = fields[2].decode("ascii", errors="strict")
            except UnicodeDecodeError as exc:
                raise CacheError("invalid bare current-tree metadata") from exc
            path = fields[3].decode("utf-8", errors="surrogateescape")
            entries.append((mode, object_type, object_id, path))

        embedded_project_roots = _embedded_project_roots(
            (entry[3] for entry in entries),
            full_name=full_name,
        )
        required = set()
        for mode, object_type, object_id, path in entries:
            if (
                mode.startswith("100")
                and object_type == "blob"
                and not _inside_embedded_project(
                    path, embedded_project_roots
                )
                and (
                    _eligible(path)
                    or os.path.basename(path) == ".gitattributes"
                )
            ):
                required.add(object_id)

        ordered = sorted(required)
        missing = []
        for offset in range(
            0, len(ordered), _CURRENT_TREE_FETCH_BATCH_OBJECTS
        ):
            batch = ordered[
                offset:offset + _CURRENT_TREE_FETCH_BATCH_OBJECTS
            ]
            request = (
                "".join(object_id + "\n" for object_id in batch)
            ).encode("ascii")
            lines = self._git_dir_bytes(
                full_name,
                "cat-file",
                "--batch-check=%(objectname) %(objecttype)",
                input_bytes=request,
                timeout=self.git_timeout,
                no_lazy=True,
            ).decode("ascii", errors="replace").splitlines()
            if len(lines) != len(batch):
                raise CacheError(
                    "bare current-tree availability response is incomplete"
                )
            for requested, line in zip(batch, lines):
                fields = line.split()
                if (
                    len(fields) != 2
                    or fields[0] != requested
                    or fields[1] not in {"blob", "missing"}
                ):
                    raise CacheError(
                        "bare current-tree path resolved to an invalid object"
                    )
                if fields[1] == "missing":
                    missing.append(requested)

        for offset in range(
            0, len(missing), _CURRENT_TREE_FETCH_BATCH_OBJECTS
        ):
            batch = missing[
                offset:offset + _CURRENT_TREE_FETCH_BATCH_OBJECTS
            ]
            request = (
                "".join(object_id + "\n" for object_id in batch)
            ).encode("ascii")
            with self._growth_reservation_locked(full_name):
                self._git_dir_bytes(
                    full_name,
                    "-c",
                    "fetch.negotiationAlgorithm=noop",
                    "fetch",
                    "origin",
                    "--quiet",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--recurse-submodules=no",
                    "--stdin",
                    input_bytes=request,
                    timeout=self.git_timeout,
                )
                self.last_network_fetch = True
            verified = self._git_dir_bytes(
                full_name,
                "cat-file",
                "--batch-check=%(objectname) %(objecttype)",
                input_bytes=request,
                timeout=self.git_timeout,
                no_lazy=True,
            ).decode("ascii", errors="replace").splitlines()
            if len(verified) != len(batch):
                raise CacheError(
                    "bare current-tree fetch response is incomplete"
                )
            for requested, line in zip(batch, verified):
                fields = line.split()
                if (
                    len(fields) != 2
                    or fields[0] != requested
                    or fields[1] != "blob"
                ):
                    raise CacheError(
                        "bare current-tree blob remained unavailable"
                    )
        return tuple(entries)

    def prune_missing_current_blobs_locked(
        self, full_name, checkout, head_sha
    ):
        """Remove policy-excluded large assets from the ephemeral index.

        The sparse direct surface has already materialized eligible source/build
        files (including unusually large own-source files up to the triage
        bound), and mature hydration fetched every ordinary-size blob. Missing
        objects are therefore large non-sparse assets; already-present objects
        are size-checked so cache warmth cannot change the policy. Removing
        those paths prevents ``git grep --cached`` from causing serial lazy
        fetches. The bare repository, commit, and evidence are unchanged.
        """
        env = _git_auth_env()
        env["GIT_NO_LAZY_FETCH"] = "1"
        command = [
            "git",
            "--git-dir",
            str(self.repo_path(full_name)),
            "-c",
            "core.commitGraph=false",
            "-c",
            "maintenance.auto=false",
            "rev-list",
            "--objects",
            "--missing=print",
            "--max-count=1",
            str(head_sha),
        ]
        result = _run_command(
            command,
            self._remaining_timeout(30),
            env=env,
        )
        if result.returncode:
            raise CacheError(
                "could not enumerate promised current-tree objects"
            )
        missing = {
            line[1:].split(None, 1)[0]
            for line in result.stdout.splitlines()
            if line.startswith("?") and len(line) > 1
        }
        tree = self._git_dir_bytes(
            full_name,
            "-c",
            "core.quotePath=false",
            "ls-tree",
            "-r",
            "-z",
            str(head_sha),
            timeout=30,
            no_lazy=True,
        )
        entries = []
        for record in tree.split(b"\0"):
            if not record:
                continue
            metadata, separator, encoded_path = record.partition(b"\t")
            fields = metadata.split()
            if not separator or len(fields) != 3 or not encoded_path:
                raise CacheError("malformed current-tree pruning entry")
            try:
                object_id = fields[2].decode("ascii", errors="strict")
            except UnicodeDecodeError as exc:
                raise CacheError(
                    "invalid current-tree pruning object id"
                ) from exc
            # Default ``ls-tree -z`` records preserve raw path bytes.  A
            # custom %(path) format still C-quotes quotes, backslashes and
            # control characters, even with quotePath disabled, which makes
            # update-index silently miss the exact tracked path.
            entries.append((object_id, os.fsdecode(encoded_path)))
        embedded_roots = _embedded_project_roots(
            (path for _object_id, path in entries),
            full_name=full_name,
        )
        policy_paths_by_object = {}
        paths = []
        for object_id, path in entries:
            own_source = (
                _eligible(path)
                and _own_source(path)
                and not _inside_embedded_project(path, embedded_roots)
            )
            if object_id in missing:
                # Sparse source surfaces have already materialized eligible
                # own source. Remaining promises are policy-excluded assets.
                paths.append(path)
            elif not own_source:
                policy_paths_by_object.setdefault(
                    object_id, []
                ).append(path)

        # A prior history traversal may have hydrated an otherwise excluded
        # current-tree asset. Apply the same declared size policy regardless
        # of cache warmth so cold and warm verdicts are byte-identical.
        policy_object_ids = sorted(policy_paths_by_object)
        for offset in range(
            0, len(policy_object_ids), _POLICY_SIZE_BATCH_OBJECTS
        ):
            batch = policy_object_ids[
                offset:offset + _POLICY_SIZE_BATCH_OBJECTS
            ]
            request = (
                "".join(object_id + "\n" for object_id in batch)
            ).encode("ascii")
            checked = self._git_dir_bytes(
                full_name,
                "cat-file",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                input_bytes=request,
                timeout=30,
                no_lazy=True,
            ).decode("ascii", errors="replace").splitlines()
            if len(checked) != len(batch):
                raise CacheError(
                    "policy asset size response is incomplete"
                )
            for requested, line in zip(batch, checked):
                fields = line.split()
                if (
                    len(fields) == 2
                    and fields[0] == requested
                    and fields[1] == "missing"
                ):
                    paths.extend(policy_paths_by_object[requested])
                    continue
                if (
                    len(fields) != 3
                    or fields[0] != requested
                    or fields[1] != "blob"
                ):
                    raise CacheError(
                        "policy asset resolved to an invalid object"
                    )
                if int(fields[2]) > MAX_SOURCE_BYTES:
                    paths.extend(policy_paths_by_object[requested])
        paths = sorted(set(paths))
        for offset in range(0, len(paths), 256):
            _run(
                [
                    "git",
                    "update-index",
                    # Sparse-checkout marks excluded paths skip-worktree.
                    # update-index otherwise silently leaves those entries in
                    # place, and the subsequent cat-file size pass may lazily
                    # fetch the promised large assets that this method found.
                    "--ignore-skip-worktree-entries",
                    "--force-remove",
                    "--",
                    *paths[offset : offset + 256],
                ],
                self._remaining_timeout(30),
                cwd=checkout,
            )
        return len(paths)

    def _history_commit_is_ancestor(self, full_name, commit):
        env = _git_auth_env()
        env["GIT_NO_LAZY_FETCH"] = "1"
        command = [
            "git",
            "--git-dir",
            str(self.repo_path(full_name)),
            "-c",
            "core.commitGraph=false",
            "-c",
            "maintenance.auto=false",
            "merge-base",
            "--is-ancestor",
            commit,
            "HEAD",
        ]
        result = _run_command(
            command, self._remaining_timeout(30), env=env
        )
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        detail = (
            result.stderr or result.stdout
            or "exit %d" % result.returncode
        ).strip()
        # A missing prior commit is expected before progressive deepening and
        # after a force-push; treat it as unreachable, not operational failure.
        folded = detail.casefold()
        if "not a valid" in folded or "unknown revision" in folded:
            return False
        raise CacheError(
            "could not validate prior history boundary: %s" % detail[:300]
        )

    def ensure_history_until_locked(
        self,
        full_name,
        *,
        required_commits=(),
        require_complete=False,
    ):
        """Progressively deepen until boundaries connect or history is complete.

        Every fetch has an explicit bounded depth. A valid prior first-use/head
        boundary stops deepening early. Missing/force-pushed boundaries continue
        to the root, which is the correctness-complete fallback.
        """
        required = tuple(sorted({
            str(commit).lower()
            for commit in required_commits
            if (
                isinstance(commit, str)
                and len(commit) == 40
                and all(c in "0123456789abcdefABCDEF" for c in commit)
            )
        }))
        deepen_fetches = 0
        step_index = 0
        with self._growth_reservation_locked(full_name):
            while True:
                shallow = self._git_dir(
                    full_name,
                    "rev-parse",
                    "--is-shallow-repository",
                    timeout=30,
                ).strip().casefold()
                complete = shallow != "true"
                reachable = tuple(
                    commit
                    for commit in required
                    if self._history_commit_is_ancestor(
                        full_name, commit
                    )
                )
                if complete or (
                    not require_complete
                    and len(reachable) == len(required)
                ):
                    return HistoryAvailability(
                        complete=complete,
                        reachable_commits=reachable,
                        deepen_fetches=deepen_fetches,
                    )
                if step_index >= len(_HISTORY_DEEPEN_STEPS):
                    raise CacheError(
                        "remote remained shallow after maximum bounded "
                        "history deepening"
                    )
                amount = _HISTORY_DEEPEN_STEPS[step_index]
                self._git_dir(
                    full_name,
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--filter=blob:none",
                    "--deepen=%d" % amount,
                    "origin",
                    timeout=self.git_timeout,
                )
                self.last_network_fetch = True
                deepen_fetches += 1
                step_index += 1

    def ensure_full_history_locked(self, full_name):
        """Progressively deepen a positive cache through the repository root."""
        return self.ensure_history_until_locked(
            full_name, require_complete=True
        )

    def ensure_history_path_blobs_locked(self, full_name, paths):
        """Hydrate only blob versions of positive evidence paths.

        A blobless full-history cache has every commit and tree, but a pickaxe
        over a frequently changed file otherwise causes one implicit promisor
        fetch per missing blob. Enumerate exact old/new blob IDs from raw path
        diffs without opening them, then request missing IDs through bounded
        ``fetch --stdin`` batches. No refs or FETCH_HEAD are written.

        The caller holds the repository lock and has deepened through every
        commit needed by its dating plan. Full fallback callers complete
        history first; validated prior-boundary reuse may stop earlier.
        """
        paths = sorted({
            str(path)
            for path in paths
            if isinstance(path, (str, os.PathLike)) and str(path)
        })
        if not paths:
            return 0

        object_ids = set()
        zero_oid = "0" * 40
        for offset in range(0, len(paths), _HISTORY_PATH_BATCH):
            batch = paths[offset:offset + _HISTORY_PATH_BATCH]
            raw = self._git_dir_bytes(
                full_name,
                "-c",
                "core.quotePath=false",
                "log",
                "--raw",
                "--root",
                "-m",
                "--no-abbrev",
                "--no-renames",
                "--format=",
                "--",
                *batch,
                timeout=self.git_timeout,
                no_lazy=True,
            ).decode("utf-8", errors="replace")
            for line in raw.splitlines():
                if not line.startswith(":"):
                    continue
                fields = line.split(None, 5)
                if len(fields) < 5:
                    raise CacheError(
                        "malformed raw path history at batch %d" % offset
                    )
                for object_id in fields[2:4]:
                    if object_id == zero_oid:
                        continue
                    if (
                        len(object_id) != 40
                        or any(
                            character not in "0123456789abcdef"
                            for character in object_id
                        )
                    ):
                        raise CacheError(
                            "invalid blob ID in raw path history"
                        )
                    object_ids.add(object_id)

        ordered = sorted(object_ids)
        missing = []
        for offset in range(
            0, len(ordered), _HISTORY_FETCH_BATCH_OBJECTS
        ):
            batch = ordered[
                offset:offset + _HISTORY_FETCH_BATCH_OBJECTS
            ]
            request = (
                "".join(object_id + "\n" for object_id in batch)
            ).encode("ascii")
            checked = self._git_dir_bytes(
                full_name,
                "cat-file",
                "--batch-check=%(objectname) %(objecttype)",
                input_bytes=request,
                timeout=self.git_timeout,
                no_lazy=True,
            )
            lines = checked.decode(
                "ascii", errors="replace"
            ).splitlines()
            if len(lines) != len(batch):
                raise CacheError(
                    "historical blob availability response is incomplete"
                )
            for requested, line in zip(batch, lines):
                fields = line.split()
                if (
                    len(fields) != 2
                    or fields[0] != requested
                    or fields[1] not in {"blob", "missing"}
                ):
                    raise CacheError(
                        "historical path resolved to an invalid object"
                    )
                if fields[1] == "missing":
                    missing.append(requested)

        if not missing:
            return 0
        with self._growth_reservation_locked(full_name):
            for offset in range(
                0, len(missing), _HISTORY_FETCH_BATCH_OBJECTS
            ):
                batch = missing[
                    offset:offset + _HISTORY_FETCH_BATCH_OBJECTS
                ]
                request = (
                    "".join(object_id + "\n" for object_id in batch)
                ).encode("ascii")
                self._git_dir_bytes(
                    full_name,
                    "-c",
                    "fetch.negotiationAlgorithm=noop",
                    "fetch",
                    "origin",
                    "--quiet",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--recurse-submodules=no",
                    # Every explicit want is already a verified blob OID.
                    # Applying blob:none here makes a promisor server return
                    # thousands of tiny one-object packs instead of coalescing
                    # the bounded batch into one pack.
                    "--stdin",
                    input_bytes=request,
                    timeout=self.git_timeout,
                )
                self.last_network_fetch = True
                verified = self._git_dir_bytes(
                    full_name,
                    "cat-file",
                    "--batch-check=%(objectname) %(objecttype)",
                    input_bytes=request,
                    timeout=self.git_timeout,
                    no_lazy=True,
                ).decode("ascii", errors="replace").splitlines()
                if len(verified) != len(batch):
                    raise CacheError(
                        "historical blob fetch response is incomplete"
                    )
                for requested, line in zip(batch, verified):
                    fields = line.split()
                    if (
                        len(fields) != 2
                        or fields[0] != requested
                        or fields[1] != "blob"
                    ):
                        raise CacheError(
                            "historical blob fetch remained incomplete"
                        )
        return len(missing)

    @staticmethod
    def _public_lfs_env():
        """Return an environment that cannot delegate public LFS auth."""
        env = os.environ.copy()
        for key in tuple(env):
            if (
                key in {
                    "GH_TOKEN",
                    "GITHUB_TOKEN",
                    "OPENALEX_API_KEY",
                    "GIT_CONFIG_COUNT",
                    "GIT_CONFIG_PARAMETERS",
                    "GIT_ASKPASS",
                    "SSH_ASKPASS",
                }
                or key.startswith("GIT_CONFIG_KEY_")
                or key.startswith("GIT_CONFIG_VALUE_")
            ):
                env.pop(key, None)
        env.update({
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_ATTR_SOURCE": "HEAD",
        })
        return env

    @staticmethod
    def _hash_file(path):
        digest = hashlib.sha256()
        with Path(path).open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _run_public_lfs(self, checkout, *args):
        command = [
            "git",
            "-C",
            str(checkout),
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=/usr/bin/false",
            "-c",
            "lfs.fetchrecentalways=false",
            "-c",
            "lfs.fetchrecentrefsdays=0",
            "-c",
            "lfs.fetchrecentcommitsdays=0",
            "lfs",
            *args,
        ]
        try:
            result = _run_command(
                command,
                self._remaining_timeout(self.git_timeout),
                env=self._public_lfs_env(),
            )
        except (TimeoutError, RuntimeError) as exc:
            raise CacheError(
                "public Git LFS command failed: %s" % str(exc)[:300]
            ) from exc
        if result.returncode:
            detail = (
                result.stderr or result.stdout
                or "exit %d" % result.returncode
            ).strip()
            raise CacheError(
                "public Git LFS object is unavailable: %s"
                % detail[:300]
            )
        return result.stdout

    def _assert_public_lfs_policy(
        self, full_name, checkout, tracked_paths
    ):
        expected = (
            "https://github.com/%s.git" % full_name
        ).rstrip("/")
        origin = self._git_dir(
            full_name,
            "config",
            "--get",
            "remote.origin.url",
            timeout=30,
        ).strip().rstrip("/")
        if origin.removesuffix(".git").casefold() != (
            expected.removesuffix(".git").casefold()
        ):
            raise CacheError(
                "public Git LFS hydration requires the canonical GitHub origin"
            )
        if any(
            os.path.basename(path).casefold() == ".lfsconfig"
            for path in tracked_paths
        ):
            raise CacheError(
                "tracked .lfsconfig is not allowed for public evidence hydration"
            )
        result = _run_command(
            [
                "git",
                "-C",
                str(checkout),
                "config",
                "--name-only",
                "--list",
            ],
            self._remaining_timeout(30),
            env=self._public_lfs_env(),
        )
        if result.returncode:
            raise CacheError(
                "could not validate local Git LFS configuration"
            )
        prohibited = re.compile(
            r"^(?:lfs\.url|remote\..*\.lfspushurl|"
            r"remote\..*\.lfsurl|lfs\.standalonetransferagent|"
            r"lfs\.customtransfer\..*|url\..*\.insteadof|"
            r"http\..*\.extraheader)$"
        )
        if any(
            prohibited.fullmatch(name.strip().casefold())
            for name in result.stdout.splitlines()
            if name.strip()
        ):
            raise CacheError(
                "custom Git LFS endpoint/transfer/auth configuration is not allowed"
            )

    def _materialize_relevant_lfs(
        self,
        full_name,
        checkout,
        head_sha,
        evidence_library_ids,
    ):
        """Hydrate exact, bounded public HEAD objects needed by detectors."""
        self.last_lfs_materialized_paths = ()
        self.last_lfs_materialization = ()
        required_ids = tuple(sorted(set(evidence_library_ids or ())))
        if not required_ids:
            return ()
        listing = _run(
            [
                "git",
                "-c",
                "core.quotePath=false",
                "ls-files",
                "--stage",
                "-z",
            ],
            self._remaining_timeout(30),
            cwd=checkout,
        )
        tracked_entries = []
        for record in listing.split("\0"):
            if not record or "\t" not in record:
                continue
            metadata, path = record.split("\t", 1)
            fields = metadata.split()
            if len(fields) < 3:
                raise CacheError(
                    "could not inspect detector-relevant sparse index"
                )
            tracked_entries.append((fields[0], path))
        tracked_paths = tuple(path for _mode, path in tracked_entries)
        embedded_roots = _embedded_project_roots(
            tracked_paths, full_name=full_name
        )
        pointers: dict[str, LFSPointer] = {}
        for mode, relpath in tracked_entries:
            if (
                _inside_embedded_project(relpath, embedded_roots)
                or not lfs_evidence_path_relevant(
                    relpath,
                    required_ids,
                )
            ):
                continue
            # Git LFS pointers are regular-file blobs.  A tracked symlink or
            # gitlink cannot be an LFS pointer and may legitimately have no
            # materialized worktree path (for example, an invalid historical
            # symlink target).  Decide from the pinned index mode before
            # touching the filesystem; regular detector surfaces remain
            # fail-closed when sparse checkout omitted them.
            if not mode.startswith("100"):
                continue
            path = Path(checkout) / relpath
            try:
                metadata = path.lstat()
            except FileNotFoundError as exc:
                raise CacheError(
                    "detector-relevant sparse path is unavailable: "
                    + relpath
                ) from exc
            if not stat.S_ISREG(metadata.st_mode):
                continue
            if metadata.st_size > 4096:
                continue
            try:
                pointer = parse_lfs_pointer(path.read_bytes())
            except TimeoutError:
                # scanner_v2's repository deadline is a TimeoutError. Do not
                # relabel an interrupted file read as a detector/LFS defect.
                raise
            except OSError as exc:
                raise CacheError(
                    "could not inspect detector-relevant LFS path: "
                    + relpath
                    + " (errno=%s)" % getattr(exc, "errno", "unknown")
                ) from exc
            if pointer is not None:
                pointers[relpath] = pointer
        if not pointers:
            return ()
        self._assert_public_lfs_policy(
            full_name, checkout, tracked_paths
        )
        if len(pointers) > _MAX_LFS_OBJECTS_PER_REPOSITORY:
            raise CacheError(
                "public Git LFS object count exceeds the evidence budget"
            )
        distinct = {
            (pointer.oid, pointer.size)
            for pointer in pointers.values()
        }
        if any(
            size > _MAX_LFS_OBJECT_BYTES for _oid, size in distinct
        ):
            raise CacheError(
                "public Git LFS object exceeds the evidence size budget"
            )
        total_bytes = sum(size for _oid, size in distinct)
        if total_bytes > _MAX_LFS_MATERIALIZED_BYTES:
            raise CacheError(
                "public Git LFS aggregate exceeds the evidence budget"
            )
        for relpath in pointers:
            if (
                relpath.startswith("-")
                or _UNSUPPORTED_LFS_PATH_RE.search(relpath)
            ):
                raise CacheError(
                    "Git LFS evidence path cannot be selected exactly"
                )

        object_root = self.repo_path(full_name) / "lfs" / "objects"
        downloaded: set[str] = set()
        provenance = []
        for relpath, pointer in sorted(pointers.items()):
            object_path = (
                object_root
                / pointer.oid[:2]
                / pointer.oid[2:4]
                / pointer.oid
            )
            object_ready = (
                object_path.is_file()
                and object_path.stat().st_size == pointer.size
                and self._hash_file(object_path) == pointer.oid
            )
            fetched = False
            if not object_ready and pointer.oid not in downloaded:
                self.network_fetch_count += 1
                # Charge the declared object size conservatively before the
                # request. A transport error or hard-cache refusal must not
                # make an attempted LFS transfer disappear from run budgets.
                self.network_materialized_bytes += pointer.size
                self.last_network_fetch = True
                with self._growth_reservation_locked(full_name):
                    self._run_public_lfs(
                        checkout,
                        "fetch",
                        "--include=/" + relpath,
                        "--exclude=",
                        "origin",
                        str(head_sha),
                    )
                downloaded.add(pointer.oid)
                fetched = True
            if (
                not object_path.is_file()
                or object_path.stat().st_size != pointer.size
                or self._hash_file(object_path) != pointer.oid
            ):
                raise CacheError(
                    "public Git LFS object failed exact SHA-256/size verification"
                )
            hydrated = Path(checkout) / relpath
            try:
                descriptor = os.open(
                    hydrated,
                    os.O_WRONLY
                    | os.O_TRUNC
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                with (
                    os.fdopen(descriptor, "wb") as destination,
                    object_path.open("rb") as source,
                ):
                    shutil.copyfileobj(
                        source, destination, length=1024 * 1024
                    )
                    destination.flush()
                    os.fsync(destination.fileno())
            except OSError as exc:
                raise CacheError(
                    "public Git LFS object could not be materialized "
                    "into the isolated worktree"
                ) from exc
            if (
                not hydrated.is_file()
                or hydrated.stat().st_size != pointer.size
                or self._hash_file(hydrated) != pointer.oid
            ):
                raise CacheError(
                    "public Git LFS checkout failed exact SHA-256/size verification"
                )
            provenance.append({
                "path": relpath,
                "oid": pointer.oid,
                "size": pointer.size,
                "head_sha": str(head_sha),
                "public_unauthenticated": True,
                "network_fetch": fetched,
            })
        self.last_lfs_materialized_paths = tuple(sorted(pointers))
        self.last_lfs_materialization = tuple(provenance)
        metadata_path = self.metadata_path(full_name)
        with self._accounting_lock():
            metadata = self._read_metadata(full_name)
            metadata["lfs_materialization"] = {
                "policy": "exact-public-head-v1",
                "head_sha": str(head_sha),
                "objects": provenance,
            }
            _write_json_atomic(metadata_path, metadata)
        return self.last_lfs_materialized_paths

    @contextlib.contextmanager
    def checkout(
        self,
        full_name,
        head_sha=None,
        *,
        evidence_library_ids=(),
    ):
        """Yield an isolated temporary worktree for the cached commit."""
        resolved = self.ensure(full_name, head_sha=head_sha)
        try:
            with self.lock(full_name):
                path = Path(tempfile.mkdtemp(
                    prefix=self.key(full_name)[:12] + "-",
                    dir=self.worktrees,
                ))
                try:
                    with self._growth_reservation_locked(full_name):
                        self._git_dir(
                            full_name, "worktree", "add", "--quiet", "--no-checkout",
                            "--detach",
                            str(path), resolved, timeout=self.git_timeout,
                        )
                        _run(
                            [
                                "git", "sparse-checkout", "set", "--no-cone",
                                *_SPARSE_PATTERNS,
                            ],
                            self._remaining_timeout(self.git_timeout),
                            cwd=path,
                        )
                        _run(
                            ["git", "checkout", "--quiet", "--detach", resolved],
                            self._remaining_timeout(self.git_timeout),
                            cwd=path,
                        )
                    self._materialize_relevant_lfs(
                        full_name,
                        path,
                        resolved,
                        evidence_library_ids,
                    )
                    yield path, resolved
                finally:
                    try:
                        self._git_dir(
                            full_name, "worktree", "remove", "--force", str(path),
                            timeout=60,
                        )
                    except CacheError:
                        if (
                            self.deadline_monotonic is None
                            or time.monotonic() < self.deadline_monotonic
                        ):
                            shutil.rmtree(path, ignore_errors=True)
                    try:
                        self._git_dir(full_name, "worktree", "prune", timeout=30)
                    except CacheError:
                        pass
        finally:
            # A partial checkout may hydrate new objects. Account for this
            # entry once, without walking every other cached repository.
            repo = self.repo_path(full_name)
            if (
                repo.exists()
                and (
                    self.deadline_monotonic is None
                    or time.monotonic() < self.deadline_monotonic
                )
            ):
                self._record_metadata(
                    full_name,
                    head_sha=resolved,
                    size=_tree_bytes(repo),
                )
                self.enforce_budget(exclude={self.key(full_name)})

    def scavenge(
        self, older_than_seconds=3600, *, cleanup_timeout_seconds=None
    ):
        """Remove stale worktrees within an optional independent allowance."""
        removed = []
        affected_prefixes = set()
        cutoff = time.time() - older_than_seconds
        cleanup_deadline = (
            None
            if cleanup_timeout_seconds is None
            else time.monotonic()
            + max(0.001, float(cleanup_timeout_seconds))
        )

        def remaining(maximum):
            if cleanup_deadline is None:
                return self._remaining_timeout(maximum)
            available = cleanup_deadline - time.monotonic()
            if available <= 0:
                raise CacheError("cache cleanup allowance is exhausted")
            return max(0.001, min(float(maximum), available))

        for path in self.worktrees.iterdir():
            if (
                cleanup_deadline is not None
                and time.monotonic() >= cleanup_deadline
            ):
                break
            try:
                if path.is_dir() and path.stat().st_mtime < cutoff:
                    shutil.rmtree(path)
                    removed.append(str(path))
                    affected_prefixes.add(path.name.split("-", 1)[0])
            except FileNotFoundError:
                continue
        # Do not launch one `git worktree prune` process for every cached repo.
        # Only repositories corresponding to a removed stale worktree can need
        # registration cleanup.
        for prefix in affected_prefixes:
            for repo in self.repos.glob(prefix + "*.git"):
                try:
                    _run(
                        ["git", "--git-dir", str(repo), "worktree", "prune"],
                        remaining(30),
                    )
                except CacheError:
                    continue
        return removed

    def size_bytes(self):
        with self._accounting_lock():
            return self._usage_locked()

    def _entries_unlocked(self):
        rows = []
        for repo in self.repos.glob("*.git"):
            key = repo.name[:-4]
            meta = self.repos / (key + ".json")
            try:
                payload = json.loads(meta.read_text()) if meta.exists() else {}
                accessed = max(repo.stat().st_mtime, float(payload.get("last_access", 0)))
            except (OSError, ValueError, TypeError):
                payload, accessed = {}, 0
            rows.append({
                "key": key,
                "repo_path": repo,
                "metadata_path": meta,
                "full_name": payload.get("full_name"),
                "last_access": accessed,
                "bytes": max(0, int(payload.get("bytes", 0) or 0)),
                "accounted_bytes": self._accounted_bytes(payload),
                "retention_priority": payload.get(
                    "retention_priority", "unclassified"
                ),
            })
        return rows

    def entries(self):
        with self._accounting_lock():
            self._usage_locked()
            return self._entries_unlocked()

    def _evict_locked(self, total, *, excluded, goal):
        """Evict unlocked LRU entries while the accounting lock is held."""
        total = max(0, int(total))
        rows = self._entries_unlocked()
        removed = []
        for row in sorted(
            rows,
            key=lambda item: (
                _RETENTION_PRIORITY_RANK.get(
                    item["retention_priority"],
                    _RETENTION_PRIORITY_RANK["unclassified"],
                ),
                item["last_access"],
            ),
        ):
            if total <= goal:
                break
            if row["key"] in excluded:
                continue
            full_name = row["full_name"]
            if not full_name:
                continue
            with self.try_lock(full_name) as acquired:
                if not acquired or not row["repo_path"].exists():
                    continue
                shutil.rmtree(row["repo_path"])
                if row["repo_path"].exists():
                    continue
                row["metadata_path"].unlink(missing_ok=True)
                total = max(0, total - row["accounted_bytes"])
                removed.append(full_name)
        return total, removed

    def enforce_budget(self, exclude=()):
        """Evict oldest entries to target after hard limit is approached."""
        excluded = set(exclude)
        with self._accounting_lock():
            total = self._usage_locked()
            if total <= self.hard_bytes:
                return []
            total, removed = self._evict_locked(
                total,
                excluded=excluded,
                goal=self.target_bytes,
            )
            self._write_usage_locked(total)
            if total > self.hard_bytes:
                raise CacheError(
                    "cache remains above hard limit after safe eviction (%d bytes)"
                    % total
                )
            return removed
