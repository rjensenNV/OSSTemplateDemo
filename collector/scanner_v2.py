"""Persistent-cache, bounded-parallel scanner orchestration for REQ-14."""

from __future__ import annotations

import concurrent.futures
import dataclasses
import json
import os
import re
import signal
import time
import uuid
from pathlib import Path

from . import scan
from .repo_cache import CacheError, RepoCache
from .triage import (
    MAX_OWN_SOURCE_BYTES,
    MAX_SOURCE_BYTES,
    BareTriageRequiresWorktree,
    triage_tree,
)


# These declarations travel with every non-legacy V2 release.  They make the
# scanner's completeness boundary explicit: only tracked current-tree text is
# evaluated, ordinary non-source assets may be pruned without weakening that
# claim, and eligible own-source is fail-closed at its separate hard ceiling.
SCAN_POLICY = {
    "name": "tracked-current-tree-text-v1",
    "ordinary_file_max_bytes": MAX_SOURCE_BYTES,
    "own_source_max_bytes": MAX_OWN_SOURCE_BYTES,
    "policy_excluded_large_assets": "pruned",
}
SCAN_FRESHNESS = {
    "basis": "resolved-default-branch-head",
    "pin": "head-sha",
}
_EXIT_SCAVENGE_ALLOWANCE_SECONDS = 5.0


class _WorkerDeadline(TimeoutError):
    pass


def _disarm_worker_alarm(previous_handler):
    """Cancel and drain SIGALRM without letting pending delivery escape."""
    if not (
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
    ):
        return
    mask = getattr(signal, "pthread_sigmask", None)
    original_mask = None
    if mask is not None:
        while True:
            try:
                original_mask = mask(
                    signal.SIG_BLOCK, {signal.SIGALRM}
                )
                break
            except _WorkerDeadline:
                # The timer may expire exactly before SIGALRM becomes blocked.
                continue
    try:
        while True:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                break
            except _WorkerDeadline:
                # A pending delivery can interrupt the cancellation call.
                continue
        if (
            original_mask is not None
            and hasattr(signal, "sigpending")
            and hasattr(signal, "sigwait")
        ):
            while signal.SIGALRM in signal.sigpending():
                signal.sigwait({signal.SIGALRM})
        while True:
            try:
                signal.signal(signal.SIGALRM, previous_handler)
                break
            except _WorkerDeadline:
                continue
    finally:
        if original_mask is not None:
            while True:
                try:
                    mask(signal.SIG_SETMASK, original_mask)
                    break
                except _WorkerDeadline:
                    continue


@dataclasses.dataclass(frozen=True)
class ScanTask:
    full_name: str
    head_sha: str | None
    candidate_library_ids: tuple[str, ...]
    estimated_size: int | None = None
    analysis_only: bool = False
    # Immutable JSON keeps process-pool tasks deterministic/hashable while
    # carrying private prior first-use proofs for changed-HEAD optimization.
    prior_first_use_boundaries: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        size = self.estimated_size
        if size is not None and (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise ValueError(
                "estimated repository size must be a non-negative integer or None"
            )
        library_ids = set()
        for value in self.prior_first_use_boundaries:
            if (
                not isinstance(value, tuple)
                or len(value) != 2
                or not all(isinstance(item, str) for item in value)
                or not value[0]
                or value[0] in library_ids
            ):
                raise ValueError(
                    "prior first-use boundaries must be unique "
                    "(library_id, JSON object) pairs"
                )
            try:
                decoded = json.loads(value[1])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "prior first-use boundary must be valid JSON"
                ) from exc
            if not isinstance(decoded, dict):
                raise ValueError(
                    "prior first-use boundary must be a JSON object"
                )
            library_ids.add(value[0])


@dataclasses.dataclass
class ScanOutcome:
    full_name: str
    head_sha: str | None
    status: str
    result: dict | None
    seconds: float
    candidate_library_ids: tuple[str, ...]
    triaged_library_ids: tuple[str, ...] = ()
    files_examined: int = 0
    bytes_examined: int = 0
    skipped_large_files: int = 0
    pruned_large_assets: int = 0
    cache_hit: bool = False
    cache_bytes: int = 0
    current_tree_triage_seconds: float = 0.0
    history_dating_seconds: float = 0.0
    analysis_seconds: float = 0.0
    git_subprocess_count: int = 0
    network_clone_count: int = 0
    network_fetch_count: int = 0
    network_materialized_bytes: int = 0
    error_code: str | None = None
    error_retryable: bool = False
    error: str | None = None


def _scan_error_contract(error) -> tuple[str, bool, str]:
    """Return a bounded, durable, machine-readable scan failure contract."""
    detail = " ".join(str(error or "repository scan failed").split())
    detail = re.sub(
        r"(?<![A-Za-z0-9_.-])/(?:Users|private|tmp|var)/[^ |]+",
        "[local-path]",
        detail,
    )
    detail = detail[:500] or "repository scan failed"
    lowered = detail.casefold()
    if "tracked notebook is invalid json" in lowered:
        return "invalid_notebook", False, detail
    if (
        "wall deadline" in lowered
        or "repo timeout" in lowered
        or "repository timeout" in lowered
        or "deadline exhausted" in lowered
    ):
        return "repository_timeout", True, detail
    # scan._run_command distinguishes its per-command cap from the enclosing
    # repository deadline and reports the former as a bounded Git command
    # failure. It is a runtime timeout, not a detector invariant. Keep the
    # match anchored to a rendered Git command so an unrelated detector
    # exception containing "timed out" remains a detector defect.
    if re.search(
        r"(?:^|:\s)git(?:\s+\S+){1,4}\s+timed out"
        r"(?:\s+after|\s+during)",
        lowered,
    ):
        return "repository_git_timeout", True, detail
    if "cancelled" in lowered or "canceled" in lowered:
        return "repository_cancelled", True, detail
    if (
        "no space left" in lowered
        or "cache hard" in lowered
        or "disk budget" in lowered
    ):
        return "repository_resource_limit", False, detail
    if any(
        marker in lowered
        for marker in (
            "git lfs object is unavailable",
            "smudge error",
            "error downloading object",
            "lfs budget",
        )
    ):
        return "repository_content_unavailable", False, detail
    if any(
        marker in lowered
        for marker in (
            "clone failed",
            "fetch failed",
            "unable to access",
            "could not resolve host",
            "connection reset",
            "connection timed out",
            "remote end hung up",
            "http 429",
            "http 5",
        )
    ):
        return "repository_transport", True, detail
    if any(
        marker in lowered
        for marker in (
            "object database",
            "missing object",
            "promisor",
            "commit-graph",
            "bad object",
            "invalid sha",
        )
    ):
        return "repository_cache_integrity", True, detail
    return "detector_error", False, detail


def _positive_history_paths(mature_probe, direct_libraries, triage):
    """Return only current evidence paths that will be dated."""
    paths = set()
    if isinstance(mature_probe, dict):
        rows = mature_probe.get("libraries", {})
        if isinstance(rows, dict):
            for row in rows.values():
                if not isinstance(row, dict):
                    continue
                paths.update(
                    path
                    for path in row.get("_dating_paths", ())
                    if isinstance(path, str) and path
                )
                component_dating = row.get("_component_dating", {})
                if isinstance(component_dating, dict):
                    for detail in component_dating.values():
                        if not isinstance(detail, dict):
                            continue
                        paths.update(
                            path
                            for path in detail.get("paths", ())
                            if isinstance(path, str) and path
                        )
    for library in direct_libraries:
        paths.update(
            path
            for path in triage.direct_files.get(library["id"], ())
            if isinstance(path, str) and path
        )
    return tuple(sorted(paths))


def _assert_lfs_history_compatible(
    hydrated_lfs_paths, positive_history_paths
):
    """Refuse a HEAD-positive whose historical LFS bytes are unavailable."""
    overlap = sorted(
        set(hydrated_lfs_paths).intersection(positive_history_paths)
    )
    if overlap:
        raise RuntimeError(
            "Git LFS object is unavailable for historical "
            "first-adoption dating: " + ", ".join(overlap[:3])
        )


def _has_lower_band_candidate(triage, library):
    coverage = set(
        library.get(
            "classification_coverage",
            ("confirmed", "bundled", "targeted"),
        )
    )
    return bool(
        coverage.intersection({"bundled", "targeted"})
        and triage.signal_files.get(library["id"])
    )


def _lower_band_only(library):
    """Keep a weaker lane from bypassing direct-use triage safeguards.

    Optimized direct triage is the confirmed authority for REQ-14 libraries.
    If it rejects a would-be import/include (for example because the namespace
    or header is project-local), the lower-band probe must not promote that
    occurrence back to confirmed through the legacy scanner.
    """
    reviewed = dict(library)
    reviewed["classification_coverage"] = [
        classification
        for classification in library.get(
            "classification_coverage",
            ("confirmed", "bundled", "targeted"),
        )
        if classification != "confirmed"
    ]
    return reviewed


def _task_prior_boundaries(task):
    decoded = {}
    for library_id, payload in task.prior_first_use_boundaries:
        value = json.loads(payload)
        if isinstance(value, dict):
            decoded[library_id] = value
    return decoded


def _prior_boundary_commits(boundaries_by_library):
    commits = set()
    for boundaries in boundaries_by_library.values():
        if not isinstance(boundaries, dict):
            continue
        for boundary in boundaries.values():
            if not isinstance(boundary, dict):
                continue
            commit = boundary.get("commit")
            if (
                isinstance(commit, str)
                and len(commit) == 40
                and all(c in "0123456789abcdefABCDEF" for c in commit)
            ):
                commits.add(commit.lower())
    return tuple(sorted(commits))


def _worker(payload):
    (task, libraries, cache_root, cache_target, cache_hard, repo_timeout,
     remote_template, run_deadline, process_group_registry,
     unknown_size_reservation) = payload
    started = time.monotonic()
    scan.reset_git_subprocess_count()
    current_tree_seconds = 0.0
    history_dating_seconds = 0.0
    analysis_seconds = 0.0
    active_stage = None
    active_stage_started = None

    def start_stage(name):
        nonlocal active_stage, active_stage_started
        if active_stage is not None:
            raise RuntimeError("scanner timing stage overlap")
        active_stage = name
        active_stage_started = time.monotonic()

    def stop_stage():
        nonlocal active_stage, active_stage_started
        nonlocal current_tree_seconds
        nonlocal history_dating_seconds, analysis_seconds
        if active_stage is None:
            return
        elapsed = max(
            0.0, time.monotonic() - active_stage_started
        )
        if active_stage == "current_tree":
            current_tree_seconds += elapsed
        elif active_stage == "history_dating":
            history_dating_seconds += elapsed
        elif active_stage == "analysis":
            analysis_seconds += elapsed
        active_stage = None
        active_stage_started = None
    effective_deadline = started + max(0.1, float(repo_timeout))
    if run_deadline is not None:
        effective_deadline = min(effective_deadline, float(run_deadline))
    remaining = effective_deadline - time.monotonic()
    if remaining <= 0:
        error_code, retryable, detail = _scan_error_contract(
            "run wall deadline exhausted before repository scan"
        )
        return ScanOutcome(
            full_name=task.full_name,
            head_sha=task.head_sha,
            status="error",
            result=None,
            seconds=0.0,
            candidate_library_ids=task.candidate_library_ids,
            error_code=error_code,
            error_retryable=retryable,
            error=detail,
        )
    cache = RepoCache(
        cache_root,
        target_bytes=cache_target,
        hard_bytes=cache_hard,
        git_timeout=max(1, int(remaining)),
        remote_template=remote_template,
        deadline_monotonic=effective_deadline,
        reservation_bytes=(
            int(task.estimated_size)
            if task.estimated_size is not None
            else min(
                int(unknown_size_reservation),
                max(64 * 1024**2, int(cache_hard) // 4),
            )
        ),
    )
    network_fetch_seen = False
    previous_deadline = scan._ACTIVE_REPO_DEADLINE[0]
    previous_process_group_registry = (
        scan._ACTIVE_PROCESS_GROUP_REGISTRY[0]
    )
    scan._ACTIVE_REPO_DEADLINE[0] = effective_deadline
    scan._ACTIVE_PROCESS_GROUP_REGISTRY[0] = process_group_registry
    previous_alarm_handler = None
    previous_terminate_handler = signal.getsignal(signal.SIGTERM)

    def terminate_worker(_signum, _frame):
        if hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)
        scan._terminate_active_process_group()
        raise _WorkerDeadline("repository worker was cancelled")

    signal.signal(signal.SIGTERM, terminate_worker)
    alarm_enabled = (
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
    )
    if alarm_enabled:
        previous_alarm_handler = signal.getsignal(signal.SIGALRM)

        def deadline_alarm(_signum, _frame):
            raise _WorkerDeadline(
                "repository wall deadline exhausted"
            )

        signal.signal(signal.SIGALRM, deadline_alarm)
        signal.setitimer(
            signal.ITIMER_REAL,
            max(0.001, effective_deadline - time.monotonic()),
        )
    try:
        library_by_id = {
            library["id"]: library for library in libraries
        }
        initial_mature = any(
            library_id in library_by_id
            and not library_by_id[library_id].get("direct_only")
            for library_id in task.candidate_library_ids
        )
        bare_triage = None
        resolved = task.head_sha
        if not task.analysis_only and not initial_mature:
            resolved = cache.ensure(task.full_name, head_sha=task.head_sha)
            network_fetch_seen = (
                network_fetch_seen or cache.last_network_fetch
            )
            start_stage("current_tree")
            try:
                with cache.lock(task.full_name):
                    bare_entries = (
                        cache.prepare_bare_current_tree_locked(
                            task.full_name, resolved
                        )
                    )
                    network_fetch_seen = (
                        network_fetch_seen or cache.last_network_fetch
                    )
                    bare_triage = triage_tree(
                        cache.repo_path(task.full_name),
                        libraries,
                        deadline_monotonic=effective_deadline,
                        full_name=task.full_name,
                        required_library_ids=(
                            task.candidate_library_ids
                        ),
                        bare_git_dir=cache.repo_path(task.full_name),
                        bare_head=resolved,
                        bare_entries=bare_entries,
                    )
            except BareTriageRequiresWorktree:
                # A custom checkout filter or working-tree encoding is rare and
                # correctness-sensitive. Preserve the old materialized path.
                bare_triage = None
            stop_stage()
            if bare_triage is not None:
                relevant = set(task.candidate_library_ids) | set(
                    bare_triage.candidate_library_ids
                )
                selected = [
                    library
                    for library in libraries
                    if library["id"] in relevant
                ]
                bare_mature = [
                    library
                    for library in selected
                    if not library.get("direct_only")
                ]
                bare_direct = [
                    library
                    for library in selected
                    if library.get("direct_only")
                ]
                direct_candidate = any(
                    bare_triage.direct_files.get(library["id"])
                    or _has_lower_band_candidate(
                        bare_triage, library
                    )
                    for library in bare_direct
                )
                if not bare_mature and not direct_candidate:
                    cache.enforce_budget(
                        exclude={cache.key(task.full_name)}
                    )
                    outcome = ScanOutcome(
                        full_name=task.full_name,
                        head_sha=resolved,
                        status="clean_reject",
                        result={},
                        seconds=time.monotonic() - started,
                        candidate_library_ids=task.candidate_library_ids,
                        triaged_library_ids=(
                            bare_triage.candidate_library_ids
                        ),
                        files_examined=bare_triage.files_examined,
                        bytes_examined=bare_triage.bytes_examined,
                        skipped_large_files=bare_triage.skipped_large,
                        pruned_large_assets=0,
                        cache_hit=not (
                            network_fetch_seen
                            or cache.last_network_fetch
                        ),
                        cache_bytes=cache.entry_size(task.full_name),
                        current_tree_triage_seconds=current_tree_seconds,
                        history_dating_seconds=history_dating_seconds,
                        analysis_seconds=analysis_seconds,
                        git_subprocess_count=scan.git_subprocess_count(),
                        network_clone_count=getattr(
                            cache, "network_clone_count", 0
                        ),
                        network_fetch_count=getattr(
                            cache, "network_fetch_count", 0
                        ),
                        network_materialized_bytes=(
                            getattr(
                                cache, "network_materialized_bytes", 0
                            )
                        ),
                    )
                    return outcome
        with cache.checkout(
            task.full_name,
            task.head_sha,
            evidence_library_ids=(
                ()
                if task.analysis_only
                else task.candidate_library_ids
            ),
        ) as (checkout, resolved):
            network_fetch_seen = (
                network_fetch_seen or cache.last_network_fetch
            )
            scan._remaining_timeout(0.1)
            messages = []
            pruned_large_assets = 0
            if task.analysis_only:
                start_stage("history_dating")
                cache.ensure_full_history_locked(task.full_name)
                stop_stage()
                start_stage("analysis")
                result = scan.analyze_repository(str(checkout))
                stop_stage()
                result["libraries"] = {}
                triaged_ids = ()
                files_examined = 0
                bytes_examined = 0
                skipped_large_files = 0
                pruned_large_assets = 0
            else:
                start_stage("current_tree")
                if initial_mature:
                    cache.ensure_current_tree_blobs_locked(
                        task.full_name, resolved
                    )
                    pruned_large_assets += (
                        cache.prune_missing_current_blobs_locked(
                            task.full_name, checkout, resolved
                        )
                    )
                triage = (
                    bare_triage
                    if bare_triage is not None
                    else triage_tree(
                        checkout,
                        libraries,
                        deadline_monotonic=effective_deadline,
                        inventory_all=initial_mature,
                        full_name=task.full_name,
                        required_library_ids=(
                            task.candidate_library_ids
                        ),
                    )
                )
                scan._remaining_timeout(0.1)
                relevant = set(task.candidate_library_ids) | set(
                    triage.candidate_library_ids
                )
                selected = [
                    library
                    for library in libraries
                    if library["id"] in relevant
                ]
                mature = [lib for lib in selected if not lib.get("direct_only")]
                direct = [lib for lib in selected if lib.get("direct_only")]
                if mature and not initial_mature:
                    cache.ensure_current_tree_blobs_locked(
                        task.full_name, resolved
                    )
                    pruned_large_assets += (
                        cache.prune_missing_current_blobs_locked(
                            task.full_name, checkout, resolved
                        )
                    )
                    triage = triage_tree(
                        checkout,
                        libraries,
                        deadline_monotonic=effective_deadline,
                        inventory_all=True,
                        existing_text=triage.current_text,
                        full_name=task.full_name,
                        required_library_ids=(
                            task.candidate_library_ids
                        ),
                    )
                    relevant.update(triage.candidate_library_ids)
                    selected = [
                        library
                        for library in libraries
                        if library["id"] in relevant
                    ]
                    mature = [
                        lib for lib in selected if not lib.get("direct_only")
                    ]
                    direct = [
                        lib for lib in selected if lib.get("direct_only")
                    ]
                    scan._remaining_timeout(0.1)
                with scan.current_tree_inventory(
                    checkout, triage.current_text
                ):
                    direct_positive_libraries = [
                        lib for lib in direct
                        if triage.direct_files.get(lib["id"])
                    ]
                    lower_band_libraries = [
                        _lower_band_only(lib) for lib in direct
                        if (
                            not triage.direct_files.get(lib["id"])
                            and _has_lower_band_candidate(triage, lib)
                        )
                    ]
                    classified_libraries = mature + lower_band_libraries
                    classified_probe = (
                        scan.scan_repo(
                            task.full_name,
                            classified_libraries,
                            messages.append,
                            repo_timeout=repo_timeout,
                            clone_attempts=1,
                            retry_delay=0,
                            checkout=str(checkout),
                            include_history=False,
                        )
                        if classified_libraries else {}
                    )
                    direct_positive = bool(direct_positive_libraries)
                    stop_stage()
                    if classified_probe is None:
                        result = None
                    else:
                        prior_boundaries = _task_prior_boundaries(task)

                        def date_positive_rows(*, require_reuse):
                            classified_rows = (
                                scan.finalize_classified_results(
                                    str(checkout),
                                    classified_probe["libraries"],
                                    classified_libraries,
                                    prior_boundaries_by_library=(
                                        prior_boundaries
                                    ),
                                    require_reuse=require_reuse,
                                )
                                if classified_probe
                                else {}
                            )
                            direct_rows = {}
                            if direct_positive_libraries:
                                # Independent direct-positive libraries can
                                # traverse the same Git object database in
                                # parallel. This is the dominant XXL-repository
                                # CPU optimization after boundary reuse.
                                executor = (
                                    concurrent.futures.ThreadPoolExecutor(
                                        max_workers=min(
                                            4,
                                            len(
                                                direct_positive_libraries
                                            ),
                                        )
                                    )
                                )
                                futures = {
                                    executor.submit(
                                        scan.direct_result_from_files,
                                        str(checkout),
                                        lib,
                                        triage.direct_files.get(
                                            lib["id"], ()
                                        ),
                                        prior_boundaries=(
                                            prior_boundaries.get(
                                                lib["id"]
                                            )
                                        ),
                                        require_reuse=require_reuse,
                                    ): lib["id"]
                                    for lib in direct_positive_libraries
                                }
                                try:
                                    for future in (
                                        concurrent.futures.as_completed(
                                            futures
                                        )
                                    ):
                                        row = future.result()
                                        if row is not None:
                                            direct_rows[
                                                futures[future]
                                            ] = row
                                except BaseException:
                                    for future in futures:
                                        future.cancel()
                                    scan._terminate_active_process_group()
                                    raise
                                finally:
                                    executor.shutdown(
                                        wait=True, cancel_futures=True
                                    )
                            return classified_rows, direct_rows

                        if classified_probe or direct_positive:
                            start_stage("history_dating")
                            history_paths = _positive_history_paths(
                                classified_probe,
                                direct,
                                triage,
                            )
                            _assert_lfs_history_compatible(
                                cache.last_lfs_materialized_paths,
                                history_paths,
                            )
                            prior_commits = _prior_boundary_commits(
                                prior_boundaries
                            )
                            partial_reuse = False
                            if prior_commits:
                                availability = (
                                    cache.ensure_history_until_locked(
                                        task.full_name,
                                        required_commits=prior_commits,
                                    )
                                )
                                partial_reuse = not availability.complete
                            else:
                                cache.ensure_full_history_locked(
                                    task.full_name
                                )
                            scan._remaining_timeout(0.1)
                            cache.ensure_history_path_blobs_locked(
                                task.full_name,
                                history_paths,
                            )
                            scan._remaining_timeout(0.1)
                            try:
                                classified_rows, direct_rows = (
                                    date_positive_rows(
                                        require_reuse=partial_reuse
                                    )
                                )
                            except scan.FirstUseReuseUnavailable:
                                # A force-push, changed evidence plan/path, or
                                # missing proof always falls back to complete
                                # history before any result can be published.
                                cache.ensure_full_history_locked(
                                    task.full_name
                                )
                                scan._remaining_timeout(0.1)
                                cache.ensure_history_path_blobs_locked(
                                    task.full_name,
                                    history_paths,
                                )
                                scan._remaining_timeout(0.1)
                                classified_rows, direct_rows = (
                                    date_positive_rows(
                                        require_reuse=False
                                    )
                                )
                            # Repository-wide AI counts are a separate,
                            # completeness-sensitive traversal. Progressive
                            # deepening may stop at a reusable first-use
                            # boundary, but publication still completes commit
                            # history before calculating those counts.
                            cache.ensure_full_history_locked(task.full_name)
                            stop_stage()
                            start_stage("analysis")
                            result = scan.analyze_repository(str(checkout))
                            stop_stage()
                            result["libraries"] = {
                                **classified_rows,
                                **{
                                    library_id: direct_rows[library_id]
                                    for library_id in sorted(direct_rows)
                                },
                            }
                        else:
                            result = {}
                    if result:
                        result["citation_cff_files"] = list(
                            triage.citation_cff
                        )
                        result["citation_cff"] = {
                            relative: triage.current_text[relative][:1_000_000]
                            for relative in triage.citation_cff
                            if relative in triage.current_text
                        }
                        result["triage"] = {
                            "files_examined": triage.files_examined,
                            "bytes_examined": triage.bytes_examined,
                            "skipped_large_files": triage.skipped_large,
                            "pruned_large_assets": pruned_large_assets,
                        }
                triaged_ids = triage.candidate_library_ids
                files_examined = triage.files_examined
                bytes_examined = triage.bytes_examined
                skipped_large_files = triage.skipped_large
            error = (
                None
                if result is not None
                else (
                    "detector scan failed: "
                    + " | ".join(messages[-3:])
                    if messages
                    else "detector scan failed"
                )
            )
            error_code, error_retryable, error_detail = (
                (None, False, None)
                if error is None
                else _scan_error_contract(error)
            )
            outcome = ScanOutcome(
                full_name=task.full_name,
                head_sha=resolved,
                status=(
                    "error" if result is None
                    else ("match" if result else "clean_reject")
                ),
                result=result,
                seconds=time.monotonic() - started,
                candidate_library_ids=task.candidate_library_ids,
                triaged_library_ids=triaged_ids,
                files_examined=files_examined,
                bytes_examined=bytes_examined,
                skipped_large_files=skipped_large_files,
                pruned_large_assets=pruned_large_assets,
                cache_hit=not (
                    network_fetch_seen or cache.last_network_fetch
                ),
                cache_bytes=0,
                current_tree_triage_seconds=current_tree_seconds,
                history_dating_seconds=history_dating_seconds,
                analysis_seconds=analysis_seconds,
                git_subprocess_count=scan.git_subprocess_count(),
                network_clone_count=getattr(
                    cache, "network_clone_count", 0
                ),
                network_fetch_count=getattr(
                    cache, "network_fetch_count", 0
                ),
                network_materialized_bytes=(
                    getattr(cache, "network_materialized_bytes", 0)
                ),
                error_code=error_code,
                error_retryable=error_retryable,
                error=error_detail,
            )
        outcome.cache_bytes = cache.entry_size(task.full_name)
        # Checkout cleanup can run final Git worktree/prune subprocesses after
        # the result row is assembled; count them before returning.
        outcome.git_subprocess_count = scan.git_subprocess_count()
        outcome.network_clone_count = getattr(
            cache, "network_clone_count", 0
        )
        outcome.network_fetch_count = getattr(
            cache, "network_fetch_count", 0
        )
        outcome.network_materialized_bytes = (
            getattr(cache, "network_materialized_bytes", 0)
        )
        return outcome
    except (CacheError, OSError, RuntimeError) as exc:
        stop_stage()
        error_code, retryable, detail = _scan_error_contract(exc)
        return ScanOutcome(
            full_name=task.full_name,
            head_sha=task.head_sha,
            status="error",
            result=None,
            seconds=time.monotonic() - started,
            candidate_library_ids=task.candidate_library_ids,
            current_tree_triage_seconds=current_tree_seconds,
            history_dating_seconds=history_dating_seconds,
            analysis_seconds=analysis_seconds,
            git_subprocess_count=scan.git_subprocess_count(),
            network_clone_count=getattr(
                cache, "network_clone_count", 0
            ),
            network_fetch_count=getattr(
                cache, "network_fetch_count", 0
            ),
            network_materialized_bytes=getattr(
                cache, "network_materialized_bytes", 0
            ),
            error_code=error_code,
            error_retryable=retryable,
            error=detail,
        )
    finally:
        if alarm_enabled:
            _disarm_worker_alarm(previous_alarm_handler)
        signal.signal(signal.SIGTERM, previous_terminate_handler)
        scan._terminate_active_process_group()
        try:
            Path(process_group_registry).unlink()
        except FileNotFoundError:
            pass
        scan._ACTIVE_PROCESS_GROUP_REGISTRY[0] = (
            previous_process_group_registry
        )
        scan._ACTIVE_REPO_DEADLINE[0] = previous_deadline


def _signal_registered_process_groups(registries, signum):
    """Signal Git sessions advertised by workers before killing the workers."""
    signaled = set()
    own_group = os.getpgrp()
    for registry in registries:
        try:
            fields = Path(registry).read_text(encoding="ascii").split()
            process_groups = [
                int(fields[index])
                for index in range(1, len(fields), 2)
            ]
        except (FileNotFoundError, IndexError, OSError, TypeError, ValueError):
            continue
        for process_group in process_groups:
            if process_group <= 1 or process_group == own_group:
                continue
            try:
                os.killpg(process_group, signum)
                signaled.add(process_group)
            except (ProcessLookupError, PermissionError):
                continue
    return signaled


def scan_many(tasks, libraries, cache_root, workers=2, repo_timeout=600,
              cache_target_bytes=200 * 1024**3,
              cache_hard_bytes=250 * 1024**3,
              remote_template="https://github.com/{full_name}.git",
              giant_threshold_bytes=2 * 1024**3,
              on_result=None,
              before_task=None,
              on_heartbeat=None,
              run_deadline=None):
    """Scan unknown tasks exclusively and bound known-giant concurrency."""
    tasks = sorted(
        tasks,
        key=lambda task: (
            task.estimated_size is not None,
            -int(task.estimated_size or 0),
            task.full_name.lower(),
        ),
    )
    cache = RepoCache(
        cache_root,
        target_bytes=cache_target_bytes,
        hard_bytes=cache_hard_bytes,
        deadline_monotonic=run_deadline,
    )
    cache.reconcile_accounting()
    cache.scavenge(older_than_seconds=0)
    outcomes = []

    registry_root = Path(cache_root).resolve() / "process-groups"
    registry_root.mkdir(parents=True, exist_ok=True)

    def payload(task, registry):
        return (
            task,
            libraries,
            str(Path(cache_root).resolve()),
            int(cache_target_bytes),
            int(cache_hard_bytes),
            int(repo_timeout),
            remote_template,
            run_deadline,
            str(registry),
            int(giant_threshold_bytes),
        )

    unknown = []
    known_giant = []
    normal = []
    for task in tasks:
        if task.estimated_size is None:
            unknown.append(task)
        elif int(task.estimated_size) >= int(giant_threshold_bytes):
            known_giant.append(task)
        else:
            normal.append(task)
    pools = []
    future_lanes = {}
    future_registries = {}
    future_tasks = {}
    future_started = {}
    deadline_expired = False
    aborted = False

    def submit_next(lane):
        nonlocal deadline_expired
        if run_deadline is not None and time.monotonic() >= float(run_deadline):
            deadline_expired = True
            return False
        try:
            task = next(lane["tasks"])
        except StopIteration:
            lane["exhausted"] = True
            return False
        # Journal attempts begin at the actual dispatch boundary. At most the
        # worker-slot count can therefore be left running after a Mac crash.
        if before_task is not None:
            before_task(task)
        registry = registry_root / (
            "%d-%s.active" % (os.getpid(), uuid.uuid4().hex)
        )
        try:
            future = lane["pool"].submit(
                _worker, payload(task, registry)
            )
        except BaseException:
            registry.unlink(missing_ok=True)
            raise
        lane["active"] += 1
        future_lanes[future] = lane
        future_registries[future] = registry
        future_tasks[future] = task
        future_started[future] = time.monotonic()
        return True

    def close_lane_if_done(lane):
        pool = lane["pool"]
        if (
            lane["exhausted"]
            and lane["active"] == 0
            and pool in pools
        ):
            # Reap a completed known-giant lane immediately. Its worker may
            # retain several GiB even though normal work is still running.
            pool.shutdown(wait=True, cancel_futures=True)
            pools.remove(pool)

    try:
        total_workers = max(1, int(workers))
        phases = []
        if unknown:
            # Missing size is a fail-safe resource classification. Nothing
            # else may overlap these serial tasks.
            phases.append(((unknown, 1),))
        if total_workers == 1:
            if known_giant:
                phases.append(((known_giant, 1),))
            if normal:
                phases.append(((normal, 1),))
        elif known_giant and normal:
            # One known giant may overlap normal work, but the two executors
            # together never exceed the configured process count.
            phases.append((
                (known_giant, 1),
                (normal, total_workers - 1),
            ))
        elif known_giant:
            phases.append(((known_giant, 1),))
        elif normal:
            phases.append(((normal, total_workers),))
        next_heartbeat = time.monotonic() + 60.0
        for phase_specs in phases:
            if (
                run_deadline is not None
                and time.monotonic() >= float(run_deadline)
            ):
                deadline_expired = True
                break
            lanes = []
            for phase_tasks, phase_workers in phase_specs:
                pool = concurrent.futures.ProcessPoolExecutor(
                    max_workers=phase_workers
                )
                pools.append(pool)
                lane = {
                    "pool": pool,
                    "tasks": iter(phase_tasks),
                    "slots": phase_workers,
                    "active": 0,
                    "exhausted": False,
                }
                lanes.append(lane)
                for _unused in range(lane["slots"]):
                    if not submit_next(lane):
                        break
                close_lane_if_done(lane)
            pending = set(future_lanes)
            while pending:
                now = time.monotonic()
                timeout = max(0.0, next_heartbeat - now)
                if run_deadline is not None:
                    remaining = max(
                        0.0, float(run_deadline) - now
                    )
                    if remaining <= 0:
                        deadline_expired = True
                        for future in pending:
                            future.cancel()
                        break
                    timeout = min(timeout, remaining)
                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=timeout,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done:
                    if (
                        run_deadline is not None
                        and time.monotonic() >= float(run_deadline)
                    ):
                        deadline_expired = True
                        for future in pending:
                            future.cancel()
                        break
                    if on_heartbeat is not None:
                        on_heartbeat()
                    next_heartbeat = time.monotonic() + 60.0
                    continue
                for future in done:
                    completed_lane = future_lanes.pop(future)
                    completed_lane["active"] -= 1
                    registry = future_registries.pop(future)
                    task = future_tasks.pop(future)
                    task_started = future_started.pop(future)
                    registry.unlink(missing_ok=True)
                    try:
                        outcome = future.result()
                    except _WorkerDeadline as exc:
                        error_code, retryable, detail = (
                            _scan_error_contract(exc)
                        )
                        outcome = ScanOutcome(
                            full_name=task.full_name,
                            head_sha=task.head_sha,
                            status="error",
                            result=None,
                            seconds=max(
                                0.0, time.monotonic() - task_started
                            ),
                            candidate_library_ids=(
                                task.candidate_library_ids
                            ),
                            error_code=error_code,
                            error_retryable=retryable,
                            error=detail,
                        )
                    outcomes.append(outcome)
                    try:
                        cache.record_outcome_priority(
                            outcome.full_name,
                            status=outcome.status,
                            cache_hit=outcome.cache_hit,
                        )
                    except (CacheError, OSError):
                        # Retention priority is reconstructible optimization
                        # metadata; never discard a completed scanner verdict
                        # because this advisory write failed.
                        pass
                    if on_result:
                        on_result(outcome)
                    submit_next(completed_lane)
                    close_lane_if_done(completed_lane)
                if time.monotonic() >= next_heartbeat:
                    if on_heartbeat is not None:
                        on_heartbeat()
                    next_heartbeat = time.monotonic() + 60.0
                pending = set(future_lanes)
            if deadline_expired:
                break
            for lane in lanes:
                close_lane_if_done(lane)
    except BaseException:
        # A coordinator checkpoint/budget failure must stop already-running
        # workers and their descendant Git commands, not merely stop queueing
        # new work while in-flight scans continue consuming the run budget.
        aborted = True
        raise
    finally:
        for future in future_lanes:
            future.cancel()
        if deadline_expired or aborted:
            registries = tuple(future_registries.values())
            _signal_registered_process_groups(
                registries, signal.SIGTERM
            )
            for pool in pools:
                for process in tuple(
                    getattr(pool, "_processes", {}).values()
                ):
                    process.terminate()
            for pool in pools:
                for process in tuple(
                    getattr(pool, "_processes", {}).values()
                ):
                    process.join(timeout=1)
                    if process.is_alive() and hasattr(process, "kill"):
                        process.kill()
            _signal_registered_process_groups(
                registries, signal.SIGKILL
            )
            for pool in pools:
                pool.shutdown(wait=False, cancel_futures=True)
        else:
            for pool in pools:
                pool.shutdown(wait=True, cancel_futures=True)
        for registry in future_registries.values():
            registry.unlink(missing_ok=True)
        # A killed or failed worker may have left a temporary worktree after
        # the startup sweep.  Exit cleanup makes this independent of the happy
        # path while keeping bare caches (and SQLite verdicts) intact.
        try:
            cache.scavenge(
                older_than_seconds=0,
                cleanup_timeout_seconds=(
                    _EXIT_SCAVENGE_ALLOWANCE_SECONDS
                ),
            )
        except (CacheError, OSError):
            # Collection has already ended. Cleanup is bounded and retried by
            # the unconditional startup sweep on the next invocation.
            pass
    outcomes.sort(key=lambda outcome: outcome.full_name.lower())
    return outcomes
