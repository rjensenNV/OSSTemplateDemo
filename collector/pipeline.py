"""Stateful, resumable REQ-14 collection pipeline.

This module owns orchestration policy.  Network adapters, scanners, citation
sources and publication are dependency-injected so the complete control flow is
fixture-testable without contacting external services or writing production
data.
"""

from __future__ import annotations

import dataclasses
import datetime
import copy
import hashlib
import json
import math
import os
import re
import resource
import shutil
import socket
import sys
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import config, discover, run
from .catalog import CATALOG, CATALOG_EVENTS
from .discovery import (
    CoverageCertificate,
    CoverageGap,
    CoveragePartition,
    DiscoveryObservation,
    DiscoveryResult,
    GitHubCodeSearch,
    SourcegraphDiscovery,
    combine_discovery_results,
    github_query_fingerprint,
    query_packs,
    signal_specs,
    sourcegraph_query_fingerprint,
)
from .discovery.base import parse_timestamp
from .fingerprints import canonical_json as fingerprint_json
from .fingerprints import FingerprintManifest, fingerprint
from .github_client import (
    GitHubGraphQLClient,
    GraphQLError,
    GraphQLResolution,
    RepositoryLookup,
    RepositoryMetadata,
)
from .nvpl_components import preserve_v1_components, reviewed_components
from .planner import RunPlan, build_plan, current_fingerprints
from .publish_v2 import stage_v2
from .repo_cache import RepoCache
from .scanner_v2 import SCAN_FRESHNESS, SCAN_POLICY, ScanTask, scan_many
from .state import StateDB


class PipelineError(RuntimeError):
    pass


class BudgetExceeded(PipelineError):
    pass


class FinalVisibilityRefreshRequired(PipelineError):
    pass


def _should_resume_final_visibility_epoch(
    *, resumed_run: bool, prior_stage_status: str | None,
    final_visibility_privacy_control: Mapping[str, Any] | None = None,
) -> bool:
    """Resume only an interrupted attestation for the same candidate set.

    A completed fresh *initial* metadata epoch is reusable input, but it is not
    proof that an older failed final-visibility epoch describes the same output
    set. After privacy reconciliation changes repository membership, the
    failed epoch must be superseded by a newly planned attestation.
    """
    return bool(
        resumed_run
        and (
            prior_stage_status in {"running", "complete"}
            or (
                prior_stage_status == "failed"
                and final_visibility_privacy_control is not None
            )
        )
    )


def _should_force_metadata_refresh_after_final_visibility(
    *,
    resumed_run: bool,
    prior_stage_status: str | None,
    reusable_fresh_metadata_epoch: bool,
    visibility_rejection_resume_control: Mapping[str, Any] | None,
) -> bool:
    """Require new metadata after a certified newest-epoch rejection."""
    return bool(
        resumed_run
        and prior_stage_status == "failed"
        and (
            not reusable_fresh_metadata_epoch
            or visibility_rejection_resume_control is not None
        )
    )


def _should_resume_incomplete_fresh_metadata_epoch(
    *,
    force_metadata_refresh: bool,
    graphql_resume_control: Mapping[str, Any] | None,
) -> bool:
    """Never reuse a prior partial-epoch certificate for a new refresh."""
    return bool(graphql_resume_control) and not force_metadata_refresh


NO_LIVE_V2_RELEASE = "no-live-v2-release"
NETWORK_TASK_LEASE_SECONDS = 300
WORK_TASK_LEASE_SECONDS = 9 * 60
METADATA_BATCH_SIZE = 50
FINAL_VISIBILITY_MAX_AGE_SECONDS = 2 * 60 * 60
WARM_NO_CHANGE_TARGET_SECONDS = 30 * 60
WARM_NO_CHANGE_CEILING_SECONDS = 60 * 60
PHASE8_MAX_OWNER_WALL_SECONDS = 7 * 24 * 60 * 60
PHASE8_ISSUE_RETRY_WORKERS = 2
PHASE8_SCAN_TASK_UNIVERSE = 38321


def _network_task_source_sha256() -> str:
    """Bind interrupted network work to the exact executable contract."""
    collector_root = Path(__file__).resolve().parent
    paths = (
        collector_root / "pipeline.py",
        collector_root / "http_transport.py",
        collector_root / "github_client.py",
        collector_root / "discovery/base.py",
        collector_root / "discovery/github_search.py",
        collector_root / "discovery/query_plan.py",
        collector_root / "discovery/sourcegraph.py",
    )
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(collector_root).as_posix().encode()
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _completed_discovery_request_count(raw_result: str | None) -> int:
    """Return the legacy logical request count from one completed document."""
    try:
        result = json.loads(raw_result or "{}")
        metrics = result["certificate"]["metrics"]
        return max(1, int(metrics.get("request_count", 0) or 0))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "completed discovery task has no valid request count"
        ) from exc


def _durable_discovery_request_usage(
    state,
    run_id: str,
) -> dict[str, Any]:
    """Compute charged HTTP attempts without double-counting lineage.

    New attempts come from the per-attempt usage journal. Exact inherited
    documents use their recorded lineage charge. Completed legacy tasks that
    predate the usage journal fall back to their validated certificate count.
    A transport-policy successor may also carry an explicit conservative
    historical charge for failed predecessor attempts whose old schema could
    not retain retry-level metrics.
    """
    run = state.connection.execute(
        "SELECT plan_json FROM runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if run is None:
        raise PipelineError("network usage run is unknown")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        execution = plan.get("execution_contract", {}) or {}
        lineage = plan.get("successor_lineage", {}) or {}
        historical = dict(
            execution.get("historical_network_request_attempts")
            or lineage.get("historical_network_request_attempts")
            or {}
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "network usage execution contract is malformed"
        ) from exc
    allowed_sources = {"github-code-search", "sourcegraph"}
    if set(historical) - allowed_sources:
        raise PipelineError("network usage contract names an unknown source")
    totals = {
        source: {
            "historical": int(historical.get(source, 0) or 0),
            "inherited": 0,
            "journaled": 0,
            "legacy_completed": 0,
        }
        for source in sorted(allowed_sources)
    }
    if any(
        values["historical"] < 0 for values in totals.values()
    ):
        raise PipelineError("historical network usage cannot be negative")

    journaled_task_ids: set[int] = set()
    for row in state.connection.execute(
        """
        SELECT task_id, source, SUM(request_attempt_count) AS requests
        FROM network_task_usage
        WHERE run_id=?
        GROUP BY task_id, source
        """,
        (run_id,),
    ):
        source = str(row["source"])
        if source not in totals:
            raise PipelineError("network usage journal names an unknown source")
        journaled_task_ids.add(int(row["task_id"]))
        totals[source]["journaled"] += int(row["requests"] or 0)

    inherited_task_ids: set[int] = set()
    for row in state.connection.execute(
        """
        SELECT ti.successor_task_id, ti.inherited_request_count,
               t.payload_json
        FROM task_inheritance ti
        JOIN tasks t ON t.task_id=ti.successor_task_id
        WHERE ti.successor_run_id=?
          AND t.stage='discovery-query'
        """,
        (run_id,),
    ):
        try:
            source = str(json.loads(row["payload_json"])["source"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "inherited network task payload is malformed"
            ) from exc
        if source not in totals:
            raise PipelineError(
                "inherited network task names an unknown source"
            )
        task_id = int(row["successor_task_id"])
        if task_id in journaled_task_ids:
            raise PipelineError(
                "inherited task unexpectedly has fresh network usage"
            )
        inherited_task_ids.add(task_id)
        totals[source]["inherited"] += int(
            row["inherited_request_count"]
        )

    for row in state.connection.execute(
        """
        SELECT task_id, payload_json, result_json
        FROM tasks
        WHERE run_id=? AND stage='discovery-query'
          AND status='complete'
        """,
        (run_id,),
    ):
        task_id = int(row["task_id"])
        if task_id in journaled_task_ids or task_id in inherited_task_ids:
            continue
        try:
            source = str(json.loads(row["payload_json"])["source"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "completed network task payload is malformed"
            ) from exc
        if source not in totals:
            raise PipelineError(
                "completed network task names an unknown source"
            )
        totals[source]["legacy_completed"] += (
            _completed_discovery_request_count(row["result_json"])
        )

    by_source = {}
    for source, values in totals.items():
        charged = sum(int(value) for value in values.values())
        by_source[source] = {**values, "charged": charged}
    return {"sources": by_source}


class _RunLockHeartbeat:
    """Renew the single-network-run lease from an independent connection."""

    def __init__(self, state_path, name, owner, lease_seconds):
        self.state_path = Path(state_path)
        self.name = name
        self.owner = owner
        self.lease_seconds = max(60.0, float(lease_seconds))
        self.interval = min(60.0, self.lease_seconds / 3.0)
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._error = None
        self._thread = threading.Thread(
            target=self._loop,
            name="collector-run-lock-heartbeat",
            daemon=True,
        )

    def start(self):
        self._thread.start()

    def _loop(self):
        try:
            with StateDB(self.state_path, auto_migrate=False) as state:
                while not self._stop.wait(self.interval):
                    if not state.renew_lock(
                        self.name,
                        owner=self.owner,
                        lease_seconds=self.lease_seconds,
                    ):
                        self._lost.set()
                        return
        except BaseException as exc:  # surfaced synchronously by verify()
            self._error = exc
            self._lost.set()

    def verify(self, state):
        if self._lost.is_set() or not state.renew_lock(
            self.name,
            owner=self.owner,
            lease_seconds=self.lease_seconds,
        ):
            detail = (
                ": %s" % self._error
                if self._error is not None
                else ""
            )
            raise PipelineError("collector network-run lock was lost%s" % detail)

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=max(5.0, self.interval + 1.0))


class _TaskLeaseHeartbeat:
    """Keep one journaled network task leased while its request is in flight.

    Discovery partitioning and rate-limit pacing can make a single logical
    task outlive the five-minute reclaim window. Renewal uses an independent
    SQLite connection so a blocked HTTP call cannot prevent it. If renewal
    fails, the original worker may finish its request but is never allowed to
    commit the result.
    """

    def __init__(
        self,
        state_path,
        task_id,
        worker,
        lease_seconds,
        *,
        interval_seconds=None,
    ):
        lease_seconds = float(lease_seconds)
        if lease_seconds <= 0:
            raise ValueError("task heartbeat lease must be positive")
        interval = (
            min(60.0, lease_seconds / 3.0)
            if interval_seconds is None
            else float(interval_seconds)
        )
        if interval <= 0 or interval >= lease_seconds:
            raise ValueError(
                "task heartbeat interval must be positive and shorter than its lease"
            )
        self.state_path = Path(state_path)
        self.task_id = int(task_id)
        self.worker = str(worker)
        self.lease_seconds = lease_seconds
        self.interval = interval
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._error = None
        self._thread = threading.Thread(
            target=self._loop,
            name="collector-network-task-heartbeat-%d" % self.task_id,
            daemon=True,
        )

    def start(self):
        self._thread.start()

    def _loop(self):
        try:
            with StateDB(self.state_path, auto_migrate=False) as state:
                while not self._stop.wait(self.interval):
                    if not state.renew_task(
                        self.task_id,
                        worker=self.worker,
                        lease_seconds=self.lease_seconds,
                    ):
                        self._lost.set()
                        return
        except BaseException as exc:  # surfaced synchronously by verify()
            self._error = exc
            self._lost.set()

    def verify(self, state):
        if self._lost.is_set():
            raise PipelineError(
                "journaled network task lease was lost"
            ) from self._error
        try:
            renewed = state.renew_task(
                self.task_id,
                worker=self.worker,
                lease_seconds=self.lease_seconds,
            )
        except BaseException as exc:
            self._error = exc
            self._lost.set()
            raise PipelineError(
                "journaled network task lease was lost"
            ) from exc
        if not renewed:
            self._lost.set()
            raise PipelineError("journaled network task lease was lost")

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=max(5.0, min(30.0, self.interval + 1.0)))


def _complete_journaled_network_task(
    state,
    state_path,
    task_id,
    worker,
    operation,
    *,
    before_complete=None,
):
    """Execute and durably complete one already-leased network task."""
    heartbeat = _TaskLeaseHeartbeat(
        state_path,
        task_id,
        worker,
        NETWORK_TASK_LEASE_SECONDS,
    )
    heartbeat.start()
    try:
        document = operation()
        # Synchronous renewal closes the interval between the last background
        # tick and task completion. A lost lease always rejects the result.
        heartbeat.verify(state)
        if before_complete is not None:
            before_complete()
    finally:
        heartbeat.stop()
    state.complete_task(
        task_id,
        worker=worker,
        result=document,
    )
    return document


class _DirectorySwap:
    """Atomically replace a directory while retaining an explicit rollback."""

    def __init__(self, staging, live):
        self.staging = Path(staging)
        self.live = Path(live)
        self.backup = self.live.with_name(
            ".%s-previous-%s" % (self.live.name, uuid.uuid4().hex)
        )
        self.installed = False
        self.committed = False

    def install(self):
        self.live.parent.mkdir(parents=True, exist_ok=True)
        if self.live.exists():
            os.replace(self.live, self.backup)
        try:
            os.replace(self.staging, self.live)
            self.installed = True
        except BaseException:
            if self.backup.exists():
                os.replace(self.backup, self.live)
            raise
        return self

    def rollback(self):
        if self.committed:
            return
        failed = self.live.with_name(
            ".%s-failed-%s" % (self.live.name, uuid.uuid4().hex)
        )
        if self.installed and self.live.exists():
            os.replace(self.live, failed)
        if self.backup.exists():
            os.replace(self.backup, self.live)
        shutil.rmtree(failed, ignore_errors=True)
        self.installed = False

    def commit(self):
        if self.committed:
            return
        shutil.rmtree(self.backup, ignore_errors=True)
        self.committed = True


def _artifact_inventory(root: Path, prefix: str) -> list[dict[str, Any]]:
    """Return a deterministic, self-verifying inventory of a public tree."""
    artifacts = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        payload = path.read_bytes()
        artifacts.append(
            {
                "path": (
                    prefix.rstrip("/")
                    + "/"
                    + path.relative_to(root).as_posix()
                ),
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return artifacts


def _stage_duration_inventory(
    state: StateDB, run_id: str
) -> dict[str, dict[str, Any]]:
    """Return secret-free wall durations for every journaled stage."""
    result = {}
    for row in state.connection.execute(
        """
        SELECT stage, status, started_at, finished_at
        FROM stages WHERE run_id=? ORDER BY stage
        """,
        (run_id,),
    ):
        seconds = None
        try:
            started = datetime.datetime.fromisoformat(
                str(row["started_at"]).replace("Z", "+00:00")
            )
            finished = datetime.datetime.fromisoformat(
                str(row["finished_at"]).replace("Z", "+00:00")
            )
            seconds = round(
                max(0.0, (finished - started).total_seconds()), 3
            )
        except (TypeError, ValueError):
            pass
        result[str(row["stage"])] = {
            "status": str(row["status"]),
            "seconds": seconds,
        }
    return result


def _task_runtime_inventory(
    state: StateDB, run_id: str
) -> dict[str, dict[str, Any]]:
    """Aggregate task status by stage and library without repo identifiers."""
    result: dict[str, dict[str, Any]] = {}
    for row in state.connection.execute(
        """
        SELECT stage, COALESCE(library_id, '_shared') AS library_id,
               status, COUNT(*) AS count
        FROM tasks WHERE run_id=?
        GROUP BY stage, COALESCE(library_id, '_shared'), status
        ORDER BY stage, library_id, status
        """,
        (run_id,),
    ):
        stage = str(row["stage"])
        library_id = str(row["library_id"])
        status = str(row["status"])
        count = int(row["count"])
        stage_row = result.setdefault(
            stage, {"total": 0, "by_status": {}, "by_library": {}}
        )
        stage_row["total"] += count
        stage_row["by_status"][status] = (
            int(stage_row["by_status"].get(status, 0)) + count
        )
        library_row = stage_row["by_library"].setdefault(
            library_id, {"total": 0, "by_status": {}}
        )
        library_row["total"] += count
        library_row["by_status"][status] = (
            int(library_row["by_status"].get(status, 0)) + count
        )
    return result


def _slo_profile(
    mode: str,
    scans: int,
    budgets: "RunBudgets",
    *,
    run_class: str | None = None,
) -> dict[str, Any]:
    if run_class == "phase8-cohort-a":
        name, target, ceiling = (
            "partial_cohort_reconciliation",
            24 * 3600,
            budgets.max_wall_seconds,
        )
    elif mode == "refresh" and scans == 0:
        name = "warm_no_change"
        target = WARM_NO_CHANGE_TARGET_SECONDS
        ceiling = min(
            budgets.max_wall_seconds,
            WARM_NO_CHANGE_CEILING_SECONDS,
        )
    elif mode == "refresh":
        name, target, ceiling = (
            "normal_weekly",
            2 * 3600,
            budgets.max_wall_seconds,
        )
    elif mode == "onboard":
        name, target, ceiling = (
            "targeted_onboarding",
            4 * 3600,
            budgets.max_wall_seconds,
        )
    else:
        name, target, ceiling = (
            "full_reconciliation",
            24 * 3600,
            budgets.max_wall_seconds,
        )
    return {
        "class": name,
        "target_seconds": target,
        "ceiling_seconds": ceiling,
    }


def _issue_retry_workers(
    run_class: str | None,
    budgets: "RunBudgets",
) -> int:
    """Keep ordinary scanning at full concurrency and isolate retries."""
    if run_class == "phase8-cohort-a":
        return max(1, min(PHASE8_ISSUE_RETRY_WORKERS, budgets.workers))
    return budgets.workers


def _phase8_runtime_issue_contract(
    error_code: str,
    retryable: bool,
    detail: str,
) -> tuple[str, bool, str]:
    """Reclassify exact cache/transport incidents, never detector evidence."""
    normalized = " ".join(str(detail or "").split())[:500]
    if (
        error_code == "detector_error"
        and normalized
        == "current-tree object is unavailable after hydration"
    ):
        return "repository_cache_integrity", True, normalized
    if (
        error_code == "detector_error"
        and re.fullmatch(
            r"repository scan exceeded [0-9]+s wall-clock cap",
            normalized,
        )
    ):
        return "repository_timeout", True, normalized
    if (
        error_code == "detector_error"
        and re.fullmatch(
            r"detector-relevant sparse path is unavailable: .+",
            normalized,
        )
    ):
        return "repository_cache_integrity", True, normalized
    if (
        error_code == "detector_error"
        and normalized
        == "public Git LFS object count exceeds the evidence budget"
    ):
        return "repository_content_unavailable", False, normalized
    if (
        error_code == "detector_error"
        and re.search(
            r"remote error: upload-pack: not our ref [0-9a-f]{40,64}(?:\Z|\s)",
            normalized,
            re.IGNORECASE,
        )
    ):
        return "repository_cache_integrity", True, normalized
    return error_code, bool(retryable), normalized


_HISTORICAL_SCAN_TIMING_FIELDS = (
    "seconds",
    "current_tree_triage_seconds",
    "history_dating_seconds",
    "analysis_seconds",
)
_HISTORICAL_SCAN_COUNT_FIELDS = (
    "git_subprocess_count",
    "git_subprocess_unknown_attempt_count",
    "network_clone_count",
    "network_clone_unknown_attempt_count",
    "network_fetch_count",
    "network_fetch_unknown_attempt_count",
    "network_materialized_bytes",
    "network_materialized_bytes_unknown_attempt_count",
)
_COMBINED_SCAN_USAGE_FIELDS = (
    *_HISTORICAL_SCAN_TIMING_FIELDS,
    "git_subprocess_count",
    "network_clone_count",
    "network_fetch_count",
    "network_materialized_bytes",
)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        fingerprint_json(value).encode("utf-8")
    ).hexdigest()


def _validate_phase8_scan_tail_deferral(value: Any) -> dict[str, Any]:
    """Validate the exact owner-authorized deferred scan-tail certificate."""
    if not isinstance(value, Mapping):
        raise PipelineError("Phase 8 scan-tail deferral must be an object")
    required = {
        "version",
        "kind",
        "policy",
        "reason",
        "authorized_at",
        "predecessor_source_commit",
        "successor_source_commit",
        "changed_paths",
        "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "task_universe_count",
        "completed_scan_task_count",
        "deferred_scan_task_count",
        "deferred_task_keys",
        "deferred_task_keys_sha256",
        "deferred_repository_proof_sha256",
        "status_counts_before",
        "status_counts_after",
        "interrupted_attempts_closed",
        "new_scan_attempts",
        "changed_scan_results",
        "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError("Phase 8 scan-tail deferral shape changed")
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    task_keys = document.get("deferred_task_keys")
    before = document.get("status_counts_before")
    after = document.get("status_counts_after")
    if (
        document.get("version") != 1
        or document.get("kind") != "phase8-owner-scan-tail-deferral"
        or document.get("policy")
        != "quarantine-exact-unresolved-repositories"
        or not isinstance(document.get("reason"), str)
        or not re.fullmatch(
            r"[a-z0-9][a-z0-9_.:-]{0,127}", document["reason"]
        )
        or not isinstance(document.get("authorized_at"), str)
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", document[field])
            for field in (
                "predecessor_source_commit",
                "successor_source_commit",
                "source_audit_sha256",
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "deferred_task_keys_sha256",
                "deferred_repository_proof_sha256",
            )
        )
        or not isinstance(document.get("changed_paths"), list)
        or document["changed_paths"] != sorted(set(document["changed_paths"]))
        or not all(isinstance(path, str) and path for path in document["changed_paths"])
        or not isinstance(task_keys, list)
        or task_keys != sorted(set(task_keys))
        or not all(
            isinstance(task_key, str)
            and re.fullmatch(r"[0-9a-f]{64}", task_key)
            for task_key in task_keys
        )
        or _canonical_sha256(task_keys)
        != document.get("deferred_task_keys_sha256")
        or document.get("task_universe_count") != PHASE8_SCAN_TASK_UNIVERSE
        or not isinstance(document.get("completed_scan_task_count"), int)
        or not isinstance(document.get("deferred_scan_task_count"), int)
        or document["deferred_scan_task_count"] != len(task_keys)
        or document["completed_scan_task_count"] + len(task_keys)
        != PHASE8_SCAN_TASK_UNIVERSE
        or not isinstance(before, Mapping)
        or not isinstance(after, Mapping)
        or set(before) != {"complete", "failed", "pending", "running"}
        or set(after) != {"complete", "failed", "pending", "running"}
        or any(
            not isinstance(count, int) or isinstance(count, bool) or count < 0
            for count in (*before.values(), *after.values())
        )
        or sum(before.values()) != PHASE8_SCAN_TASK_UNIVERSE
        or sum(after.values()) != PHASE8_SCAN_TASK_UNIVERSE
        or after != {
            "complete": document["completed_scan_task_count"],
            "failed": document["deferred_scan_task_count"],
            "pending": 0,
            "running": 0,
        }
        or not isinstance(document.get("interrupted_attempts_closed"), int)
        or document["interrupted_attempts_closed"] < 0
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError("Phase 8 scan-tail deferral is invalid")
    return dict(value)


def _validate_phase8_scan_tail_resume_control(
    value: Any,
    deferral: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact grouping and terminal-state resume correction."""
    if not isinstance(value, Mapping):
        raise PipelineError("Phase 8 scan-tail resume control must be an object")
    required = {
        "version",
        "kind",
        "policy",
        "predecessor_source_commit",
        "successor_source_commit",
        "changed_paths",
        "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "scan_tail_deferral_contract_sha256",
        "task_universe_count",
        "completed_scan_task_count",
        "deferred_scan_task_count",
        "deferred_task_keys_sha256",
        "deferred_repository_proof_sha256",
        "preserved_state_sha256",
        "pre_control_status_counts",
        "post_control_status_counts",
        "pre_control_task_status_sha256",
        "post_control_task_status_sha256",
        "reterminalized_scan_task_count",
        "new_scan_attempts",
        "changed_scan_results",
        "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError("Phase 8 scan-tail resume control shape changed")
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "collector/state.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py",
    ]
    if (
        document.get("version") != 1
        or document.get("kind") != "phase8-scan-tail-resume-control"
        or document.get("policy")
        != "whole-repository-quarantine-grouping-compatibility"
        or document.get("predecessor_source_commit")
        != "55574deb6598dc332530750e40c56b629c157f91"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit",
                "successor_source_commit",
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "scan_tail_deferral_contract_sha256",
                "deferred_task_keys_sha256",
                "deferred_repository_proof_sha256",
                "preserved_state_sha256",
                "pre_control_task_status_sha256",
                "post_control_task_status_sha256",
            )
        )
        or document.get("changed_paths") != expected_paths
        or document.get("scan_tail_deferral_contract_sha256")
        != deferral.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != deferral.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or document.get("task_universe_count")
        != deferral.get("task_universe_count")
        or document.get("completed_scan_task_count")
        != deferral.get("completed_scan_task_count")
        or document.get("deferred_scan_task_count")
        != deferral.get("deferred_scan_task_count")
        or document.get("deferred_task_keys_sha256")
        != deferral.get("deferred_task_keys_sha256")
        or document.get("deferred_repository_proof_sha256")
        != deferral.get("deferred_repository_proof_sha256")
        or not isinstance(document.get("pre_control_status_counts"), Mapping)
        or set(document["pre_control_status_counts"])
        != {"complete", "failed", "pending", "running"}
        or document["pre_control_status_counts"].get("complete")
        != deferral.get("completed_scan_task_count")
        or document["pre_control_status_counts"].get("failed", 0)
        + document["pre_control_status_counts"].get("pending", 0)
        != deferral.get("deferred_scan_task_count")
        or document["pre_control_status_counts"].get("running") != 0
        or document.get("post_control_status_counts")
        != deferral.get("status_counts_after")
        or not isinstance(
            document.get("reterminalized_scan_task_count"), int
        )
        or isinstance(document["reterminalized_scan_task_count"], bool)
        or document["reterminalized_scan_task_count"]
        != document["pre_control_status_counts"].get("pending")
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError("Phase 8 scan-tail resume control is invalid")
    return dict(value)


def _validate_phase8_downstream_resume_control(
    value: Any,
    tail_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact post-OpenAlex publication-semantics correction."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 downstream resume control must be an object"
        )
    required = {
        "version",
        "kind",
        "policy",
        "predecessor_source_commit",
        "successor_source_commit",
        "changed_paths",
        "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "scan_tail_resume_contract_sha256",
        "task_universe_count",
        "completed_scan_task_count",
        "deferred_scan_task_count",
        "scan_attempt_count",
        "scan_result_count",
        "citation_cache_entry_count",
        "repaired_deferred_scan_task_count",
        "pre_repair_deferred_tasks_sha256",
        "repair_source_deferred_tasks_sha256",
        "post_repair_deferred_tasks_sha256",
        "repair_source_scan_attempts_sha256",
        "repair_source_scan_results_sha256",
        "preserved_state_sha256",
        "new_scan_attempts",
        "changed_scan_results",
        "changed_citation_cache_entries",
        "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 downstream resume control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "collector/validate_v2.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
        "test_req14_publication.py",
    ]
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-downstream-resume-control"
        or document.get("policy")
        != "publication-semantics-and-exact-deferred-task-repair-no-network-work"
        or document.get("predecessor_source_commit")
        != "c02882128a069d84bfe3e6102648aaf5738efff3"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit",
                "successor_source_commit",
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "scan_tail_resume_contract_sha256",
                "pre_repair_deferred_tasks_sha256",
                "repair_source_deferred_tasks_sha256",
                "post_repair_deferred_tasks_sha256",
                "repair_source_scan_attempts_sha256",
                "repair_source_scan_results_sha256",
                "preserved_state_sha256",
            )
        )
        or document.get("scan_tail_resume_contract_sha256")
        != tail_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != tail_resume.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or document.get("task_universe_count")
        != tail_resume.get("task_universe_count")
        or document.get("completed_scan_task_count")
        != tail_resume.get("completed_scan_task_count")
        or document.get("deferred_scan_task_count")
        != tail_resume.get("deferred_scan_task_count")
        or not isinstance(
            document.get("repaired_deferred_scan_task_count"), int
        )
        or isinstance(
            document["repaired_deferred_scan_task_count"], bool
        )
        or document["repaired_deferred_scan_task_count"]
        not in {0, document["deferred_scan_task_count"]}
        or document["repair_source_deferred_tasks_sha256"]
        != document["post_repair_deferred_tasks_sha256"]
        or (
            document["repaired_deferred_scan_task_count"] == 0
            and document["pre_repair_deferred_tasks_sha256"]
            != document["post_repair_deferred_tasks_sha256"]
        )
        or (
            document["repaired_deferred_scan_task_count"] > 0
            and document["pre_repair_deferred_tasks_sha256"]
            == document["post_repair_deferred_tasks_sha256"]
        )
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < minimum
            for field, minimum in (
                ("scan_attempt_count", 0),
                ("scan_result_count", 0),
                ("citation_cache_entry_count", 0),
            )
        )
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError("Phase 8 downstream resume control is invalid")
    return dict(value)


def _validate_phase8_visibility_resume_control(
    value: Any,
    downstream_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact missing-node metadata-refresh correction."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 visibility resume control must be an object"
        )
    required = {
        "version",
        "kind",
        "policy",
        "predecessor_source_commit",
        "successor_source_commit",
        "changed_paths",
        "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "downstream_resume_contract_sha256",
        "visibility_epoch",
        "failed_visibility_task_key",
        "missing_repository_node_sha256",
        "visibility_batch_count",
        "completed_visibility_batch_count",
        "pending_visibility_batch_count",
        "preserved_state_sha256",
        "new_scan_attempts",
        "changed_scan_results",
        "changed_citation_cache_entries",
        "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 visibility resume control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-visibility-resume-control"
        or document.get("policy")
        != "force-fresh-metadata-after-exact-missing-node"
        or document.get("predecessor_source_commit")
        != "75693f5a14187713e2b04bbd5ce8bb3ac1114fc5"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit",
                "successor_source_commit",
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "downstream_resume_contract_sha256",
                "missing_repository_node_sha256",
                "preserved_state_sha256",
            )
        )
        or document.get("downstream_resume_contract_sha256")
        != downstream_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != downstream_resume.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("visibility_epoch"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", document["visibility_epoch"])
        or not isinstance(document.get("failed_visibility_task_key"), str)
        or not document["failed_visibility_task_key"].startswith(
            "epoch:" + document["visibility_epoch"][:16] + ":batch:"
        )
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in (
                "visibility_batch_count",
                "completed_visibility_batch_count",
                "pending_visibility_batch_count",
            )
        )
        or document["completed_visibility_batch_count"] < 1
        or document["visibility_batch_count"]
        != (
            document["completed_visibility_batch_count"]
            + document["pending_visibility_batch_count"]
        )
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError("Phase 8 visibility resume control is invalid")
    return dict(value)


def _validate_phase8_graphql_resume_control(
    value: Any,
    visibility_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact embedded-usage and partial-epoch correction."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 GraphQL resume control must be an object"
        )
    required = {
        "version",
        "kind",
        "policy",
        "predecessor_source_commit",
        "successor_source_commit",
        "changed_paths",
        "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "visibility_resume_contract_sha256",
        "preseeded_metadata_contract_sha256",
        "embedded_result_universe_sha256",
        "embedded_task_count",
        "embedded_request_count",
        "embedded_points_used",
        "fresh_metadata_epoch",
        "completed_fresh_metadata_batch_count",
        "pending_fresh_metadata_batch_count",
        "retry_pending_fresh_metadata_batch_count",
        "raw_graphql_points_used",
        "reconciled_graphql_points_used",
        "preserved_state_sha256",
        "new_scan_attempts",
        "changed_scan_results",
        "changed_citation_cache_entries",
        "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 GraphQL resume control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    count_fields = (
        "embedded_task_count",
        "embedded_request_count",
        "embedded_points_used",
        "completed_fresh_metadata_batch_count",
        "pending_fresh_metadata_batch_count",
        "retry_pending_fresh_metadata_batch_count",
        "raw_graphql_points_used",
        "reconciled_graphql_points_used",
    )
    if (
        document.get("version") != 1
        or document.get("kind") != "phase8-graphql-resume-control"
        or document.get("policy")
        != "deduplicate-embedded-preseeded-usage-and-resume-fresh-epoch"
        or document.get("predecessor_source_commit")
        != "b826e8345304502c381be45ecce2a44de399bd7b"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit",
                "successor_source_commit",
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "visibility_resume_contract_sha256",
                "preseeded_metadata_contract_sha256",
                "embedded_result_universe_sha256",
                "preserved_state_sha256",
            )
        )
        or document.get("visibility_resume_contract_sha256")
        != visibility_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != visibility_resume.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("fresh_metadata_epoch"), str)
        or not re.fullmatch(
            r"[0-9a-f]{16}", document["fresh_metadata_epoch"]
        )
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in count_fields
        )
        or document["embedded_task_count"] < 1
        or document["embedded_request_count"] < 1
        or document["embedded_points_used"] < 1
        or document["completed_fresh_metadata_batch_count"] < 1
        or document["pending_fresh_metadata_batch_count"] < 1
        or document["retry_pending_fresh_metadata_batch_count"]
        > document["pending_fresh_metadata_batch_count"]
        or document["raw_graphql_points_used"]
        != document["reconciled_graphql_points_used"]
        + document["embedded_points_used"]
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError("Phase 8 GraphQL resume control is invalid")
    return dict(value)


def _validate_phase8_privacy_resume_control(
    value: Any,
    graphql_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact fresh-metadata privacy/scan reconciliation."""
    if not isinstance(value, Mapping):
        raise PipelineError("Phase 8 privacy resume control must be an object")
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "graphql_resume_contract_sha256", "prior_scan_task_count",
        "current_scan_task_count", "current_completed_scan_task_count",
        "current_deferred_scan_task_count", "purged_scan_task_count",
        "purged_completed_scan_task_count", "purged_deferred_scan_task_count",
        "purged_task_keys_sha256", "purged_repository_nodes_sha256",
        "remaining_deferred_task_keys", "remaining_deferred_task_keys_sha256",
        "remaining_deferred_repository_proof_sha256", "scan_head_pin_count",
        "scan_bound_rename_count", "fresh_metadata_epoch",
        "fresh_metadata_batch_count", "preserved_state_sha256",
        "new_scan_attempts", "changed_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError("Phase 8 privacy resume control shape changed")
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py", "collector/phase8_tail_control.py",
        "collector/pipeline.py", "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md", "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    remaining = document.get("remaining_deferred_task_keys")
    count_fields = (
        "prior_scan_task_count", "current_scan_task_count",
        "current_completed_scan_task_count",
        "current_deferred_scan_task_count", "purged_scan_task_count",
        "purged_completed_scan_task_count", "purged_deferred_scan_task_count",
        "scan_head_pin_count", "scan_bound_rename_count",
        "fresh_metadata_batch_count",
    )
    if (
        document.get("version") != 1
        or document.get("kind") != "phase8-privacy-resume-control"
        or document.get("policy")
        != "purge-nonpublic-and-pin-surviving-scan-evidence"
        or document.get("predecessor_source_commit")
        != "4ebb8d6db10171aa3e06117f8e62dce94ac01d38"
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in ("predecessor_source_commit", "successor_source_commit")
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256", "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "graphql_resume_contract_sha256", "purged_task_keys_sha256",
                "purged_repository_nodes_sha256",
                "remaining_deferred_task_keys_sha256",
                "remaining_deferred_repository_proof_sha256",
                "preserved_state_sha256",
            )
        )
        or document.get("graphql_resume_contract_sha256")
        != graphql_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != graphql_resume.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool) or document[field] < 0
            for field in count_fields
        )
        or not isinstance(remaining, list)
        or len(remaining) != document["current_deferred_scan_task_count"]
        or remaining != sorted(set(remaining))
        or any(
            not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key)
            for key in remaining
        )
        or _canonical_sha256(remaining)
        != document["remaining_deferred_task_keys_sha256"]
        or document["prior_scan_task_count"]
        != document["current_scan_task_count"] + document["purged_scan_task_count"]
        or document["purged_scan_task_count"]
        != document["purged_completed_scan_task_count"]
        + document["purged_deferred_scan_task_count"]
        or document["current_scan_task_count"]
        != document["current_completed_scan_task_count"]
        + document["current_deferred_scan_task_count"]
        or not isinstance(document.get("fresh_metadata_epoch"), str)
        or not re.fullmatch(r"[0-9a-f]{16}", document["fresh_metadata_epoch"])
        or document["fresh_metadata_batch_count"] < 1
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError("Phase 8 privacy resume control is invalid")
    return dict(value)


def _validate_phase8_fresh_candidate_deferral_control(
    value: Any,
    privacy_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact post-refresh candidates deferred by the owner."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 fresh-candidate deferral control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "privacy_resume_contract_sha256", "scan_task_universe_count",
        "completed_scan_task_count", "owner_deferred_scan_task_count",
        "deferred_repository_count", "deferred_task_proof",
        "deferred_task_proof_sha256", "preserved_state_sha256",
        "new_scan_attempts", "changed_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 fresh-candidate deferral control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    proof = document.get("deferred_task_proof")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    count_fields = (
        "scan_task_universe_count", "completed_scan_task_count",
        "owner_deferred_scan_task_count", "deferred_repository_count",
    )
    proof_valid = isinstance(proof, list) and proof == sorted(
        proof, key=lambda item: item.get("task_key", "")
        if isinstance(item, Mapping) else ""
    )
    if proof_valid:
        for item in proof:
            if (
                not isinstance(item, Mapping)
                or set(item) != {
                    "task_key", "repository_identity_sha256", "libraries"
                }
                or not isinstance(item.get("task_key"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["task_key"])
                or not isinstance(
                    item.get("repository_identity_sha256"), str
                )
                or not re.fullmatch(
                    r"[0-9a-f]{64}", item["repository_identity_sha256"]
                )
                or not isinstance(item.get("libraries"), list)
                or not item["libraries"]
                or item["libraries"] != sorted(set(item["libraries"]))
                or not all(
                    isinstance(library_id, str) and library_id
                    for library_id in item["libraries"]
                )
            ):
                proof_valid = False
                break
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-fresh-candidate-deferral-control"
        or document.get("policy")
        != "owner-defer-unscanned-post-refresh-candidates"
        or document.get("predecessor_source_commit")
        != "c97fe1a2f6d8e1f3c1d413707c41ee5da7187e51"
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in ("predecessor_source_commit", "successor_source_commit")
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256", "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "privacy_resume_contract_sha256",
                "deferred_task_proof_sha256", "preserved_state_sha256",
            )
        )
        or document.get("privacy_resume_contract_sha256")
        != privacy_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != privacy_resume.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in count_fields
        )
        or not proof_valid
        or len(proof) != document.get("deferred_repository_count")
        or len({item["task_key"] for item in proof}) != len(proof)
        or len({item["repository_identity_sha256"] for item in proof})
        != len(proof)
        or _canonical_sha256(proof)
        != document.get("deferred_task_proof_sha256")
        or document.get("scan_task_universe_count")
        != privacy_resume.get("current_scan_task_count")
        or document.get("completed_scan_task_count")
        != privacy_resume.get("current_completed_scan_task_count")
        or document.get("owner_deferred_scan_task_count")
        != privacy_resume.get("current_deferred_scan_task_count")
        or document.get("deferred_repository_count", 0) < 1
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 fresh-candidate deferral control is invalid"
        )
    return dict(value)


def _validate_phase8_visibility_set_resume_control(
    value: Any,
    fresh_candidate_deferral: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact failed-epoch supersession correction."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 visibility-set resume control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "fresh_candidate_deferral_contract_sha256",
        "fresh_metadata_epoch", "fresh_metadata_batch_count",
        "prior_visibility_epoch", "prior_visibility_set_sha256",
        "prior_visibility_task_count",
        "prior_visibility_completed_task_count",
        "prior_visibility_pending_task_count", "preserved_state_sha256",
        "new_scan_attempts", "changed_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 visibility-set resume control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    count_fields = (
        "fresh_metadata_batch_count", "prior_visibility_task_count",
        "prior_visibility_completed_task_count",
        "prior_visibility_pending_task_count",
    )
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-visibility-set-resume-control"
        or document.get("policy")
        != "supersede-failed-visibility-epoch-after-fresh-metadata"
        or document.get("predecessor_source_commit")
        != "05a4e6a335ef3527c5a03326a656175a0103380f"
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit", "successor_source_commit"
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "fresh_candidate_deferral_contract_sha256",
                "prior_visibility_set_sha256", "preserved_state_sha256",
            )
        )
        or document.get("fresh_candidate_deferral_contract_sha256")
        != fresh_candidate_deferral.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != fresh_candidate_deferral.get(
            "current_network_task_source_sha256"
        )
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("fresh_metadata_epoch"), str)
        or not re.fullmatch(
            r"[0-9a-f]{16}", document["fresh_metadata_epoch"]
        )
        or not isinstance(document.get("prior_visibility_epoch"), str)
        or not re.fullmatch(
            r"[0-9a-f]{32}", document["prior_visibility_epoch"]
        )
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in count_fields
        )
        or document.get("fresh_metadata_batch_count", 0) < 1
        or document.get("prior_visibility_task_count", 0) < 1
        or document.get("prior_visibility_task_count")
        != document.get("prior_visibility_completed_task_count")
        + document.get("prior_visibility_pending_task_count")
        or document.get("prior_visibility_completed_task_count", 0) < 1
        or document.get("prior_visibility_pending_task_count", 0) < 1
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 visibility-set resume control is invalid"
        )
    return dict(value)


def _validate_phase8_visibility_rejection_resume_control(
    value: Any,
    visibility_set_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact post-supersession missing-node refresh control."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 visibility-rejection resume control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "visibility_set_resume_contract_sha256", "visibility_epoch",
        "failed_visibility_task_key", "missing_repository_node_sha256",
        "visibility_batch_count", "completed_visibility_batch_count",
        "pending_visibility_batch_count", "preserved_state_sha256",
        "new_scan_attempts", "changed_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 visibility-rejection resume control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-visibility-rejection-resume-control"
        or document.get("policy")
        != "force-fresh-metadata-after-newest-missing-node"
        or document.get("predecessor_source_commit")
        != "450eae2a0bac4d55d70e5aa9a5df099a20c2cf16"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit", "successor_source_commit"
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "visibility_set_resume_contract_sha256",
                "missing_repository_node_sha256",
                "preserved_state_sha256",
            )
        )
        or document.get("visibility_set_resume_contract_sha256")
        != visibility_set_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != visibility_set_resume.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("visibility_epoch"), str)
        or not re.fullmatch(
            r"[0-9a-f]{32}", document["visibility_epoch"]
        )
        or not isinstance(
            document.get("failed_visibility_task_key"), str
        )
        or not document["failed_visibility_task_key"].startswith(
            "epoch:" + document["visibility_epoch"][:16] + ":batch:"
        )
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in (
                "visibility_batch_count",
                "completed_visibility_batch_count",
                "pending_visibility_batch_count",
            )
        )
        or document["completed_visibility_batch_count"] < 1
        or document["pending_visibility_batch_count"] < 1
        or document["visibility_batch_count"] != (
            document["completed_visibility_batch_count"]
            + document["pending_visibility_batch_count"]
        )
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 visibility-rejection resume control is invalid"
        )
    return dict(value)


def _validate_phase8_visibility_refresh_resume_control(
    value: Any,
    visibility_rejection_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact prior-partial-epoch precedence correction."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 visibility-refresh resume control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "visibility_rejection_resume_contract_sha256",
        "prior_fresh_metadata_epoch",
        "prior_completed_fresh_metadata_batch_count",
        "collision_pending_fresh_metadata_batch_count",
        "collision_fresh_metadata_task_set_sha256",
        "preserved_state_sha256", "new_metadata_request_count",
        "new_scan_attempts", "changed_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 visibility-refresh resume control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-visibility-refresh-resume-control"
        or document.get("policy")
        != "new-refresh-never-resumes-prior-partial-epoch"
        or document.get("predecessor_source_commit")
        != "6d39e84a6f26d0c0c5c1f153b0fbbcd02f39a0d5"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit", "successor_source_commit"
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "visibility_rejection_resume_contract_sha256",
                "collision_fresh_metadata_task_set_sha256",
                "preserved_state_sha256",
            )
        )
        or document.get("visibility_rejection_resume_contract_sha256")
        != visibility_rejection_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != visibility_rejection_resume.get(
            "current_network_task_source_sha256"
        )
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("prior_fresh_metadata_epoch"), str)
        or not re.fullmatch(
            r"[0-9a-f]{16}", document["prior_fresh_metadata_epoch"]
        )
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 1
            for field in (
                "prior_completed_fresh_metadata_batch_count",
                "collision_pending_fresh_metadata_batch_count",
            )
        )
        or document["prior_completed_fresh_metadata_batch_count"]
        != document["collision_pending_fresh_metadata_batch_count"]
        or document.get("new_metadata_request_count") != 0
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 visibility-refresh resume control is invalid"
        )
    return dict(value)


def _validate_phase8_visibility_budget_resume_control(
    value: Any,
    visibility_refresh_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the unchanged-budget, cohort-only metadata batching control."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 visibility-budget resume control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "visibility_refresh_resume_contract_sha256",
        "prior_metadata_batch_size", "current_metadata_batch_size",
        "metadata_lookup_count", "planned_metadata_batch_count",
        "planned_final_visibility_batch_count",
        "journaled_graphql_points", "remaining_graphql_point_budget",
        "projected_unit_cost_graphql_points", "max_graphql_points",
        "preserved_state_sha256", "new_metadata_request_count",
        "new_scan_attempts", "changed_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 visibility-budget resume control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py",
        "collector/phase8_tail_control.py",
        "collector/pipeline.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    integer_fields = (
        "prior_metadata_batch_size", "current_metadata_batch_size",
        "metadata_lookup_count", "planned_metadata_batch_count",
        "planned_final_visibility_batch_count",
        "journaled_graphql_points", "remaining_graphql_point_budget",
        "projected_unit_cost_graphql_points", "max_graphql_points",
    )
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-visibility-budget-resume-control"
        or document.get("policy")
        != "cohort-only-100-lookup-batches-with-unchanged-budget"
        or document.get("predecessor_source_commit")
        != "1b4ce9f401133aa689338a443ba5a575fad2039b"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit", "successor_source_commit"
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "visibility_refresh_resume_contract_sha256",
                "preserved_state_sha256",
            )
        )
        or document.get("visibility_refresh_resume_contract_sha256")
        != visibility_refresh_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != visibility_refresh_resume.get(
            "current_network_task_source_sha256"
        )
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in integer_fields
        )
        or document.get("prior_metadata_batch_size") != 50
        or document.get("current_metadata_batch_size") != 100
        or document.get("metadata_lookup_count", 0) < 1
        or document.get("planned_final_visibility_batch_count", 0) < 1
        or document.get("planned_metadata_batch_count")
        != (
            document["metadata_lookup_count"]
            + document["current_metadata_batch_size"] - 1
        ) // document["current_metadata_batch_size"]
        or document.get("max_graphql_points") != 2500
        or document.get("remaining_graphql_point_budget")
        != document["max_graphql_points"] - document["journaled_graphql_points"]
        or document.get("projected_unit_cost_graphql_points")
        != document["journaled_graphql_points"]
        + document["planned_metadata_batch_count"]
        + document["planned_final_visibility_batch_count"]
        or document["projected_unit_cost_graphql_points"]
        > document["max_graphql_points"]
        or document.get("new_metadata_request_count") != 0
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 visibility-budget resume control is invalid"
        )
    return dict(value)


def _validate_phase8_visibility_transport_retry_control(
    value: Any,
    visibility_budget_resume: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one conservative point reserve for one malformed response."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 visibility transport retry control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "visibility_budget_resume_contract_sha256", "retry_task_id",
        "retry_task_key_sha256", "retry_metadata_epoch",
        "completed_new_metadata_batch_count",
        "pending_new_metadata_batch_count", "failed_attempt_count",
        "reserved_unobserved_points", "journaled_observed_points",
        "projected_graphql_points_with_reserve", "max_graphql_points",
        "preserved_state_sha256", "new_metadata_request_count",
        "new_scan_attempts", "changed_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 visibility transport retry control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py", "collector/phase8_tail_control.py",
        "collector/pipeline.py", "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md", "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    integer_fields = (
        "retry_task_id", "completed_new_metadata_batch_count",
        "pending_new_metadata_batch_count", "failed_attempt_count",
        "reserved_unobserved_points", "journaled_observed_points",
        "projected_graphql_points_with_reserve", "max_graphql_points",
    )
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-visibility-transport-retry-control"
        or document.get("policy")
        != "reserve-one-point-for-one-malformed-graphql-response"
        or document.get("predecessor_source_commit")
        != "c3198c950c52be0380f45eb40d1538adef61eb61"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit", "successor_source_commit"
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256", "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "visibility_budget_resume_contract_sha256",
                "retry_task_key_sha256", "preserved_state_sha256",
            )
        )
        or document.get("visibility_budget_resume_contract_sha256")
        != visibility_budget_resume.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != visibility_budget_resume.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("retry_metadata_epoch"), str)
        or not re.fullmatch(r"[0-9a-f]{16}", document["retry_metadata_epoch"])
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in integer_fields
        )
        or document.get("retry_task_id", 0) < 1
        or document.get("completed_new_metadata_batch_count", 0) < 1
        or document.get("pending_new_metadata_batch_count", 0) < 1
        or document.get("failed_attempt_count") != 1
        or document.get("reserved_unobserved_points") != 1
        or document.get("max_graphql_points") != 2500
        or document.get("projected_graphql_points_with_reserve")
        != visibility_budget_resume["projected_unit_cost_graphql_points"] + 1
        or document["projected_graphql_points_with_reserve"]
        > document["max_graphql_points"]
        or document.get("new_metadata_request_count") != 0
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 visibility transport retry control is invalid"
        )
    return dict(value)


def _validate_phase8_visibility_epoch_recovery_control(
    value: Any,
    transport_retry: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate exact recovery of the superseded resumable metadata epoch."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 visibility epoch recovery control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "visibility_transport_retry_contract_sha256", "reference_state_name",
        "resume_metadata_epoch", "replacement_metadata_epoch",
        "resume_epoch_batch_count", "resume_epoch_completed_batch_count",
        "restored_pending_batch_count", "replacement_completed_batch_count",
        "replacement_pending_batch_count", "additional_failed_attempt_count",
        "additional_reserved_unobserved_points",
        "total_reserved_unobserved_points", "journaled_points_before_reserve",
        "projected_graphql_points_with_reserves", "max_graphql_points",
        "restored_task_rows_sha256", "replacement_task_rows_sha256",
        "preserved_non_task_state_sha256", "new_metadata_request_count",
        "new_scan_attempts", "changed_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 visibility epoch recovery control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py", "collector/phase8_tail_control.py",
        "collector/pipeline.py", "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md", "test_req14_phase8_tail_control.py",
        "test_req14_pipeline.py",
    ]
    integers = (
        "resume_epoch_batch_count", "resume_epoch_completed_batch_count",
        "restored_pending_batch_count", "replacement_completed_batch_count",
        "replacement_pending_batch_count", "additional_failed_attempt_count",
        "additional_reserved_unobserved_points",
        "total_reserved_unobserved_points", "journaled_points_before_reserve",
        "projected_graphql_points_with_reserves", "max_graphql_points",
    )
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-visibility-epoch-recovery-control"
        or document.get("policy")
        != "restore-certified-current-epoch-and-retain-replacement-evidence"
        or document.get("predecessor_source_commit")
        != "f4df8cc4a7d0be1d75b7a17a8b39d427f12ef2ee"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit", "successor_source_commit"
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256", "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "visibility_transport_retry_contract_sha256",
                "restored_task_rows_sha256", "replacement_task_rows_sha256",
                "preserved_non_task_state_sha256",
            )
        )
        or document.get("visibility_transport_retry_contract_sha256")
        != transport_retry.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != transport_retry.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("reference_state_name"), str)
        or not document["reference_state_name"].endswith(".sqlite3")
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{16}", document[field])
            for field in ("resume_metadata_epoch", "replacement_metadata_epoch")
        )
        or document.get("resume_metadata_epoch")
        == document.get("replacement_metadata_epoch")
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in integers
        )
        or document.get("resume_epoch_batch_count") != 388
        or document.get("resume_epoch_completed_batch_count") != 189
        or document.get("restored_pending_batch_count") != 199
        or document.get("replacement_completed_batch_count") != 10
        or document.get("replacement_pending_batch_count") != 378
        or document.get("additional_failed_attempt_count") != 1
        or document.get("additional_reserved_unobserved_points") != 1
        or document.get("total_reserved_unobserved_points") != 2
        or document.get("max_graphql_points") != 2500
        or document.get("projected_graphql_points_with_reserves") != 2483
        or document["projected_graphql_points_with_reserves"]
        > document["max_graphql_points"]
        or document.get("new_metadata_request_count") != 0
        or document.get("new_scan_attempts") != 0
        or document.get("changed_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 visibility epoch recovery control is invalid"
        )
    return dict(value)


def _validate_phase8_post_refresh_privacy_control(
    value: Any,
    privacy_resume: Mapping[str, Any],
    epoch_recovery: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the one additional privacy purge from the recovered epoch."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 post-refresh privacy control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "privacy_resume_contract_sha256",
        "visibility_epoch_recovery_contract_sha256", "reference_state_name",
        "fresh_metadata_epoch", "fresh_metadata_batch_count",
        "prior_scan_task_count", "current_scan_task_count",
        "prior_completed_scan_task_count",
        "current_completed_scan_task_count",
        "current_deferred_scan_task_count",
        "additional_purged_scan_task_count",
        "additional_purged_completed_scan_task_count",
        "additional_purged_deferred_scan_task_count",
        "additional_purged_repository_count",
        "additional_purged_candidate_count",
        "additional_purged_scan_result_count",
        "additional_purged_repo_analysis_count",
        "additional_purged_task_keys_sha256",
        "additional_purged_repository_nodes_sha256",
        "additional_purged_evidence_sha256",
        "fresh_missing_metadata_proof_sha256",
        "remaining_deferred_task_keys",
        "remaining_deferred_task_keys_sha256",
        "remaining_deferred_repository_proof_sha256",
        "deferred_scan_head_pin_count", "deferred_scan_head_pins",
        "deferred_scan_head_pins_sha256",
        "scan_head_pin_count", "scan_bound_rename_count",
        "deferred_timestamp_refresh_count",
        "deferred_timestamp_refresh_rows_sha256",
        "remaining_scan_task_rows_sha256", "preserved_state_sha256",
        "new_metadata_request_count", "new_scan_attempts",
        "changed_surviving_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
        "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 post-refresh privacy control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py", "collector/phase8_tail_control.py",
        "collector/pipeline.py", "collector/state.py",
        "docs/Documentation.md", "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py", "test_req14_pipeline.py",
    ]
    remaining = document.get("remaining_deferred_task_keys")
    deferred_head_pins = document.get("deferred_scan_head_pins")
    integer_fields = (
        "fresh_metadata_batch_count", "prior_scan_task_count",
        "current_scan_task_count", "prior_completed_scan_task_count",
        "current_completed_scan_task_count",
        "current_deferred_scan_task_count",
        "additional_purged_scan_task_count",
        "additional_purged_completed_scan_task_count",
        "additional_purged_deferred_scan_task_count",
        "additional_purged_repository_count",
        "additional_purged_candidate_count",
        "additional_purged_scan_result_count",
        "additional_purged_repo_analysis_count", "scan_head_pin_count",
        "scan_bound_rename_count", "deferred_scan_head_pin_count",
        "deferred_timestamp_refresh_count",
        "new_metadata_request_count",
        "new_scan_attempts", "changed_surviving_scan_results",
        "changed_citation_cache_entries", "other_budget_changes",
    )
    if (
        document.get("version") != 2
        or document.get("kind")
        != "phase8-post-refresh-privacy-control"
        or document.get("policy")
        != "adopt-one-additional-nonpublic-purge-and-pin-surviving-evidence"
        or document.get("predecessor_source_commit")
        != "0d6d2e43b8a6f719fcade685363d11a8774a1457"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit", "successor_source_commit"
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in (
                "source_audit_sha256", "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
                "privacy_resume_contract_sha256",
                "visibility_epoch_recovery_contract_sha256",
                "additional_purged_task_keys_sha256",
                "additional_purged_repository_nodes_sha256",
                "additional_purged_evidence_sha256",
                "fresh_missing_metadata_proof_sha256",
                "remaining_deferred_task_keys_sha256",
                "remaining_deferred_repository_proof_sha256",
                "deferred_scan_head_pins_sha256",
                "deferred_timestamp_refresh_rows_sha256",
                "remaining_scan_task_rows_sha256", "preserved_state_sha256",
            )
        )
        or document.get("privacy_resume_contract_sha256")
        != privacy_resume.get("contract_sha256")
        or document.get("visibility_epoch_recovery_contract_sha256")
        != epoch_recovery.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != epoch_recovery.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("reference_state_name"), str)
        or not document["reference_state_name"].endswith(".sqlite3")
        or document.get("fresh_metadata_epoch")
        != epoch_recovery.get("resume_metadata_epoch")
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in integer_fields
        )
        or document.get("fresh_metadata_batch_count") != 388
        or document.get("prior_scan_task_count")
        != privacy_resume.get("current_scan_task_count")
        or document.get("prior_completed_scan_task_count")
        != privacy_resume.get("current_completed_scan_task_count")
        or document.get("prior_scan_task_count") != 38287
        or document.get("current_scan_task_count") != 38286
        or document.get("prior_completed_scan_task_count") != 37969
        or document.get("current_completed_scan_task_count") != 37968
        or document.get("current_deferred_scan_task_count") != 318
        or document.get("additional_purged_scan_task_count") != 1
        or document.get("additional_purged_completed_scan_task_count") != 1
        or document.get("additional_purged_deferred_scan_task_count") != 0
        or document.get("additional_purged_repository_count") != 1
        or document.get("additional_purged_candidate_count") != 3
        or document.get("additional_purged_scan_result_count") != 3
        or document.get("additional_purged_repo_analysis_count") != 2
        or document.get("scan_head_pin_count") != 1538
        or document.get("scan_bound_rename_count") != 16
        or document.get("deferred_scan_head_pin_count") != 8
        or not isinstance(deferred_head_pins, list)
        or deferred_head_pins != sorted(
            deferred_head_pins,
            key=lambda item: item.get("task_key", "")
            if isinstance(item, Mapping) else "",
        )
        or len(deferred_head_pins)
        != document["deferred_scan_head_pin_count"]
        or any(
            not isinstance(item, Mapping)
            or set(item) != {
                "task_key", "repository_identity_sha256", "head_sha",
                "libraries",
            }
            or not isinstance(item.get("task_key"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["task_key"])
            or not isinstance(
                item.get("repository_identity_sha256"), str
            )
            or not re.fullmatch(
                r"[0-9a-f]{64}", item["repository_identity_sha256"]
            )
            or not isinstance(item.get("head_sha"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", item["head_sha"])
            or not isinstance(item.get("libraries"), list)
            or not item["libraries"]
            or item["libraries"] != sorted(set(item["libraries"]))
            or not all(
                isinstance(library_id, str) and library_id
                for library_id in item["libraries"]
            )
            for item in deferred_head_pins
        )
        or len({
            item["task_key"] for item in deferred_head_pins
        }) != len(deferred_head_pins)
        or len({
            item["repository_identity_sha256"]
            for item in deferred_head_pins
        }) != len(deferred_head_pins)
        or _canonical_sha256(deferred_head_pins)
        != document.get("deferred_scan_head_pins_sha256")
        or document.get("deferred_timestamp_refresh_count") != 318
        or not isinstance(remaining, list)
        or remaining != sorted(set(remaining))
        or len(remaining) != document["current_deferred_scan_task_count"]
        or any(
            not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key)
            for key in remaining
        )
        or _canonical_sha256(remaining)
        != document.get("remaining_deferred_task_keys_sha256")
        or document["current_scan_task_count"]
        != document["current_completed_scan_task_count"]
        + document["current_deferred_scan_task_count"]
        or document["prior_scan_task_count"]
        != document["current_scan_task_count"]
        + document["additional_purged_scan_task_count"]
        or document["prior_completed_scan_task_count"]
        != document["current_completed_scan_task_count"]
        + document["additional_purged_completed_scan_task_count"]
        or document.get("new_metadata_request_count") != 0
        or document.get("new_scan_attempts") != 0
        or document.get("changed_surviving_scan_results") != 0
        or document.get("changed_citation_cache_entries") != 0
        or document.get("other_budget_changes") != 0
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 post-refresh privacy control is invalid"
        )
    return dict(value)


def _validate_phase8_final_visibility_privacy_control(
    value: Any,
    post_refresh: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact final-visibility missing-node quarantine."""
    if not isinstance(value, Mapping):
        raise PipelineError(
            "Phase 8 final-visibility privacy control must be an object"
        )
    required = {
        "version", "kind", "policy", "predecessor_source_commit",
        "successor_source_commit", "changed_paths", "source_audit_sha256",
        "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "post_refresh_privacy_contract_sha256", "final_visibility_epoch",
        "final_visibility_task_count",
        "final_visibility_completed_task_count",
        "final_visibility_pending_task_count", "rejected_task_id",
        "rejected_task_key_sha256", "rejected_repository_node_sha256",
        "rejected_repository_identity_sha256",
        "rejected_final_visibility_proof_sha256",
        "prior_scan_task_count", "current_scan_task_count",
        "prior_completed_scan_task_count",
        "current_completed_scan_task_count",
        "current_deferred_scan_task_count", "purged_scan_task_count",
        "purged_completed_scan_task_count",
        "purged_deferred_scan_task_count", "purged_repository_count",
        "purged_candidate_count", "purged_scan_result_count",
        "purged_repo_analysis_count", "purged_scan_attempt_count",
        "purged_task_key_sha256",
        "purged_evidence_sha256", "remaining_deferred_task_keys",
        "remaining_deferred_task_keys_sha256",
        "remaining_deferred_repository_proof_sha256",
        "deferred_scan_head_pin_count", "deferred_scan_head_pins",
        "deferred_scan_head_pins_sha256", "scan_head_pin_count",
        "scan_bound_rename_count", "preserved_final_visibility_tasks_sha256",
        "preserved_citation_cache_sha256", "new_metadata_request_count",
        "new_final_visibility_request_count", "new_scan_attempts",
        "changed_surviving_scan_results", "changed_citation_cache_entries",
        "other_budget_changes", "contract_sha256",
    }
    if set(value) != required:
        raise PipelineError(
            "Phase 8 final-visibility privacy control shape changed"
        )
    document = dict(value)
    contract_sha256 = document.pop("contract_sha256")
    expected_paths = [
        "collector/cli.py", "collector/phase8_tail_control.py",
        "collector/pipeline.py", "collector/state.py",
        "docs/Documentation.md", "docs/PROJECT-CONTEXT.md",
        "test_req14_phase8_tail_control.py", "test_req14_pipeline.py",
    ]
    remaining = document.get("remaining_deferred_task_keys")
    deferred_head_pins = document.get("deferred_scan_head_pins")
    integer_fields = (
        "final_visibility_task_count",
        "final_visibility_completed_task_count",
        "final_visibility_pending_task_count", "rejected_task_id",
        "prior_scan_task_count", "current_scan_task_count",
        "prior_completed_scan_task_count",
        "current_completed_scan_task_count",
        "current_deferred_scan_task_count", "purged_scan_task_count",
        "purged_completed_scan_task_count",
        "purged_deferred_scan_task_count", "purged_repository_count",
        "purged_candidate_count", "purged_scan_result_count",
        "purged_repo_analysis_count", "purged_scan_attempt_count",
        "deferred_scan_head_pin_count",
        "scan_head_pin_count", "scan_bound_rename_count",
        "new_metadata_request_count",
        "new_final_visibility_request_count", "new_scan_attempts",
        "changed_surviving_scan_results", "changed_citation_cache_entries",
        "other_budget_changes",
    )
    digest_fields = (
        "source_audit_sha256", "prior_network_task_source_sha256",
        "current_network_task_source_sha256",
        "post_refresh_privacy_contract_sha256",
        "rejected_task_key_sha256", "rejected_repository_node_sha256",
        "rejected_repository_identity_sha256",
        "rejected_final_visibility_proof_sha256", "purged_task_key_sha256",
        "purged_evidence_sha256", "remaining_deferred_task_keys_sha256",
        "remaining_deferred_repository_proof_sha256",
        "deferred_scan_head_pins_sha256",
        "preserved_final_visibility_tasks_sha256",
        "preserved_citation_cache_sha256",
    )
    if (
        document.get("version") != 1
        or document.get("kind")
        != "phase8-final-visibility-privacy-control"
        or document.get("policy")
        != "purge-one-final-missing-node-and-resume-compatible-epoch"
        or document.get("predecessor_source_commit")
        != "f31ec517980c74f07e650129f49647ab000b252a"
        or document.get("successor_source_commit")
        == document.get("predecessor_source_commit")
        or document.get("changed_paths") != expected_paths
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{40}", document[field])
            for field in (
                "predecessor_source_commit", "successor_source_commit"
            )
        )
        or any(
            not isinstance(document.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", document[field])
            for field in digest_fields
        )
        or document.get("post_refresh_privacy_contract_sha256")
        != post_refresh.get("contract_sha256")
        or document.get("prior_network_task_source_sha256")
        != post_refresh.get("current_network_task_source_sha256")
        or document.get("current_network_task_source_sha256")
        == document.get("prior_network_task_source_sha256")
        or not isinstance(document.get("final_visibility_epoch"), str)
        or not re.fullmatch(
            r"[0-9a-f]{32}", document["final_visibility_epoch"]
        )
        or any(
            not isinstance(document.get(field), int)
            or isinstance(document[field], bool)
            or document[field] < 0
            for field in integer_fields
        )
        or document.get("final_visibility_task_count") != 291
        or document.get("final_visibility_completed_task_count") != 172
        or document.get("final_visibility_pending_task_count") != 119
        or document["final_visibility_task_count"]
        != document["final_visibility_completed_task_count"]
        + document["final_visibility_pending_task_count"]
        or document.get("rejected_task_id") != 414688
        or document.get("prior_scan_task_count") != 38286
        or document.get("current_scan_task_count") != 38285
        or document.get("prior_completed_scan_task_count") != 37968
        or document.get("current_completed_scan_task_count") != 37967
        or document.get("current_deferred_scan_task_count") != 318
        or document.get("purged_scan_task_count") != 1
        or document.get("purged_completed_scan_task_count") != 1
        or document.get("purged_deferred_scan_task_count") != 0
        or document.get("purged_repository_count") != 1
        or document.get("purged_candidate_count") != 8
        or document.get("purged_scan_result_count") != 2
        or document.get("purged_repo_analysis_count") != 2
        or document.get("purged_scan_attempt_count") != 1
        or document.get("scan_head_pin_count") != 1538
        or document.get("scan_bound_rename_count") != 16
        or document.get("deferred_scan_head_pin_count") != 8
        or not isinstance(deferred_head_pins, list)
        or deferred_head_pins != post_refresh.get("deferred_scan_head_pins")
        or _canonical_sha256(deferred_head_pins)
        != document.get("deferred_scan_head_pins_sha256")
        or not isinstance(remaining, list)
        or remaining != post_refresh.get("remaining_deferred_task_keys")
        or len(remaining) != document["current_deferred_scan_task_count"]
        or remaining != sorted(set(remaining))
        or _canonical_sha256(remaining)
        != document.get("remaining_deferred_task_keys_sha256")
        or document.get("remaining_deferred_repository_proof_sha256")
        != post_refresh.get("remaining_deferred_repository_proof_sha256")
        or document["current_scan_task_count"]
        != document["current_completed_scan_task_count"]
        + document["current_deferred_scan_task_count"]
        or document["prior_scan_task_count"]
        != document["current_scan_task_count"]
        + document["purged_scan_task_count"]
        or document["prior_completed_scan_task_count"]
        != document["current_completed_scan_task_count"]
        + document["purged_completed_scan_task_count"]
        or any(document.get(field) != 0 for field in (
            "new_metadata_request_count",
            "new_final_visibility_request_count", "new_scan_attempts",
            "changed_surviving_scan_results",
            "changed_citation_cache_entries", "other_budget_changes",
        ))
        or not isinstance(contract_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
        or _canonical_sha256(document) != contract_sha256
    ):
        raise PipelineError(
            "Phase 8 final-visibility privacy control is invalid"
        )
    return dict(value)


def _phase8_final_visibility_rejected_node(
    state: StateDB,
    run_id: str,
    control: Mapping[str, Any],
) -> str:
    """Recover the private-safe rejected node only from its sealed task."""
    row = state.connection.execute(
        """
        SELECT task_id,task_key,status,payload_json,result_json
        FROM tasks WHERE run_id=?
          AND stage='github-final-visibility-batch' AND task_id=?
        """,
        (run_id, control["rejected_task_id"]),
    ).fetchone()
    if row is None or row["status"] != "complete":
        raise PipelineError("certified final-visibility task changed")
    try:
        payload = json.loads(row["payload_json"] or "{}")
        result = json.loads(row["result_json"] or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "certified final-visibility proof is malformed"
        ) from exc
    repositories = result.get("repositories")
    rejected = [
        repository for repository in repositories or []
        if repository.get("status") != "ok"
    ]
    if len(rejected) != 1:
        raise PipelineError("certified final-visibility rejection changed")
    repository = rejected[0]
    node_id = repository.get("requested_node_id")
    proof = {
        "task_id": int(row["task_id"]),
        "task_key_sha256": hashlib.sha256(
            str(row["task_key"]).encode("utf-8")
        ).hexdigest(),
        "payload_sha256": _canonical_sha256(payload),
        "repository": repository,
    }
    if (
        payload.get("epoch") != control["final_visibility_epoch"]
        or not isinstance(node_id, str)
        or not node_id
        or repository.get("requested_full_name") is not None
        or repository.get("node_id") is not None
        or repository.get("full_name") is not None
        or repository.get("status") != "missing"
        or repository.get("admitted_public") is not False
        or repository.get("error_count") != 0
        or hashlib.sha256(str(row["task_key"]).encode("utf-8")).hexdigest()
        != control["rejected_task_key_sha256"]
        or hashlib.sha256(node_id.encode("utf-8")).hexdigest()
        != control["rejected_repository_node_sha256"]
        or _canonical_sha256(proof)
        != control["rejected_final_visibility_proof_sha256"]
    ):
        raise PipelineError("certified final-visibility rejection changed")
    return node_id


def _phase8_effective_privacy_control(
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    privacy = _validate_phase8_privacy_resume_control(
        contract.get("privacy_resume_control"),
        contract.get("graphql_resume_control") or {},
    )
    post_refresh = contract.get("post_refresh_privacy_control")
    if post_refresh is None:
        return privacy
    post = _validate_phase8_post_refresh_privacy_control(
        post_refresh,
        privacy,
        contract.get("visibility_epoch_recovery_control") or {},
    )
    final_visibility = contract.get("final_visibility_privacy_control")
    if final_visibility is None:
        return post
    return _validate_phase8_final_visibility_privacy_control(
        final_visibility, post
    )


def _apply_phase8_scan_tail_deferral(
    state: StateDB,
    run_id: str,
    grouped: Mapping[str, set[str]],
    publishable: Mapping[str, RepositoryMetadata],
    contract: Mapping[str, Any],
) -> tuple[dict[str, set[str]], dict[str, Any]]:
    """Remove only the certified unresolved repositories from this release."""
    deferral = _validate_phase8_scan_tail_deferral(
        contract.get("scan_tail_deferral")
    )
    privacy = contract.get("privacy_resume_control")
    privacy_control = (
        _phase8_effective_privacy_control(contract)
        if privacy is not None
        else None
    )
    keys = tuple(
        privacy_control["remaining_deferred_task_keys"]
        if privacy_control is not None
        else deferral["deferred_task_keys"]
    )
    placeholders = ",".join("?" for _ in keys)
    rows = state.connection.execute(
        f"""
        SELECT task_key,status,payload_json,repository_id,error_code
        FROM tasks
        WHERE run_id=? AND stage='scan' AND task_key IN ({placeholders})
        ORDER BY task_key
        """,
        (run_id, *keys),
    ).fetchall()
    if len(rows) != len(keys) or [row["task_key"] for row in rows] != list(keys):
        raise PipelineError("Phase 8 deferred scan task set changed")
    filtered = {name: set(ids) for name, ids in grouped.items()}
    proof_rows = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
            full_name = payload["full_name"]
            head_sha = payload["head_sha"]
            libraries = sorted(payload["libraries"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PipelineError("Phase 8 deferred scan payload is invalid") from exc
        item = (
            next(
                (
                    candidate for candidate in publishable.values()
                    if candidate.node_id == row["repository_id"]
                ),
                None,
            )
            if privacy_control is not None
            else publishable.get(full_name)
        )
        if (
            row["status"] != "failed"
            or not isinstance(full_name, str)
            or not isinstance(libraries, list)
            or not all(isinstance(library_id, str) for library_id in libraries)
            or (
                item is not None
                and (
                    item.node_id != row["repository_id"]
                    or item.head_oid != head_sha
                )
            )
        ):
            raise PipelineError("Phase 8 deferred repository identity changed")
        # Cross-library scans may add exact candidates after the immutable
        # task payload was created.  The owner decision quarantines the whole
        # repository, so remove every currently grouped library for this exact
        # public identity.  A repository already absent from current public
        # metadata/grouping is safely quarantined by that absence.
        filtered.pop(item.full_name if item is not None else full_name, None)
        proof_rows.append({
            "task_key": row["task_key"],
            "repository_id": row["repository_id"],
            "full_name": full_name,
            "head_sha": head_sha,
            "libraries": libraries,
        })
    expected_proof = (
        privacy_control["remaining_deferred_repository_proof_sha256"]
        if privacy_control is not None
        else deferral["deferred_repository_proof_sha256"]
    )
    if _canonical_sha256(proof_rows) != expected_proof:
        raise PipelineError("Phase 8 deferred repository proof changed")
    return filtered, {
        "owner_deferred": True,
        "deferred_repositories": len(rows),
        "completed_repositories": (
            privacy_control["current_completed_scan_task_count"]
            if privacy_control is not None
            else deferral["completed_scan_task_count"]
        ),
        "task_universe_repositories": (
            privacy_control["current_scan_task_count"]
            if privacy_control is not None
            else deferral["task_universe_count"]
        ),
        "deferred_task_keys_sha256": (
            privacy_control["remaining_deferred_task_keys_sha256"]
            if privacy_control is not None
            else deferral["deferred_task_keys_sha256"]
        ),
        "deferred_repository_proof_sha256": expected_proof,
        "deferral_contract_sha256": deferral["contract_sha256"],
    }


def _pin_phase8_scan_bound_metadata(
    state: StateDB,
    run_id: str,
    publishable: Mapping[str, RepositoryMetadata],
    contract: Mapping[str, Any],
) -> dict[str, RepositoryMetadata]:
    """Keep surviving evidence bound to its scanned head after privacy refresh."""
    control = _phase8_effective_privacy_control(contract)
    rows = state.connection.execute(
        """
        SELECT repository_id,payload_json FROM tasks
        WHERE run_id=? AND stage='scan' ORDER BY task_key
        """,
        (run_id,),
    ).fetchall()
    if len(rows) != control["current_scan_task_count"]:
        raise PipelineError("Phase 8 scan-bound metadata universe changed")
    bound = {}
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
            bound[str(row["repository_id"])] = (
                str(payload["head_sha"]), str(payload["full_name"])
            )
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PipelineError("Phase 8 scan-bound payload changed") from exc
    pinned = {}
    head_changes = 0
    renames = 0
    for name, item in publishable.items():
        identity = bound.get(item.node_id)
        if identity is None:
            pinned[name] = item
            continue
        head_sha, scanned_name = identity
        head_changes += int(item.head_oid != head_sha)
        renames += int(item.full_name.casefold() != scanned_name.casefold())
        pinned[name] = dataclasses.replace(item, head_oid=head_sha)
        state.connection.execute(
            "UPDATE repositories SET head_sha=? WHERE node_id=?",
            (head_sha, item.node_id),
        )
    if (
        head_changes != control["scan_head_pin_count"]
        or renames != control["scan_bound_rename_count"]
    ):
        raise PipelineError("Phase 8 scan-bound metadata delta changed")
    deferral = contract.get("fresh_candidate_deferral_control")
    deferred_proof = (
        deferral.get("deferred_task_proof", [])
        if isinstance(deferral, Mapping)
        else []
    )
    if deferred_proof:
        manifest_row = state.connection.execute(
            "SELECT fingerprints_json FROM runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        try:
            manifest = json.loads(
                manifest_row["fingerprints_json"] if manifest_row else "{}"
            )
            detector_fps = {}
            for library_id, values in manifest["libraries"].items():
                filter_values = {"shared": manifest["filters"]["shared"]}
                if library_id == "nvpl":
                    filter_values["nvpl"] = manifest["filters"]["nvpl"]
                detector_fps[library_id] = fingerprint(
                    "library:%s:effective-detector" % library_id,
                    {
                        "detector": values["detector"],
                        "filters": filter_values,
                    },
                )
        except (
            AttributeError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
        ) as exc:
            raise PipelineError(
                "Phase 8 deferred scan fingerprint manifest changed"
            ) from exc
        proof_by_identity = {
            item["repository_identity_sha256"]: item
            for item in deferred_proof
        }
        control_head_pins = control.get("deferred_scan_head_pins", [])
        head_pin_by_identity = {
            item["repository_identity_sha256"]: item
            for item in control_head_pins
        }
        if control_head_pins and (
            len(control_head_pins) != len(deferred_proof)
            or {
                (
                    item["task_key"],
                    item["repository_identity_sha256"],
                    tuple(item["libraries"]),
                )
                for item in control_head_pins
            }
            != {
                (
                    item["task_key"],
                    item["repository_identity_sha256"],
                    tuple(item["libraries"]),
                )
                for item in deferred_proof
            }
        ):
            raise PipelineError(
                "Phase 8 deferred scan-bound control changed"
            )
        matched_control_pins = set()
        for name, item in list(pinned.items()):
            identity_sha256 = hashlib.sha256(
                (item.node_id + "\0" + name).encode("utf-8")
            ).hexdigest()
            proof = proof_by_identity.get(identity_sha256)
            if proof is None:
                continue
            libraries = sorted(proof["libraries"])

            def deferred_task_key(head_sha):
                return fingerprint(
                    "scan-task-v2",
                    {
                        "repository_node_id": item.node_id,
                        "head_sha": head_sha,
                        "candidate_library_ids": libraries,
                        "analysis_only": False,
                        "ai_fingerprint": None,
                        "detector_fingerprints": {
                            library_id: detector_fps.get(library_id)
                            for library_id in libraries
                        },
                    },
                )

            control_pin = head_pin_by_identity.get(identity_sha256)
            if control_pin is not None:
                pinned_head = control_pin["head_sha"]
                if deferred_task_key(pinned_head) != proof["task_key"]:
                    raise PipelineError(
                        "Phase 8 deferred scan-bound control changed"
                    )
                matched_control_pins.add(identity_sha256)
            else:
                if control_head_pins:
                    raise PipelineError(
                        "Phase 8 deferred scan-bound control changed"
                    )
                if deferred_task_key(item.head_oid) == proof["task_key"]:
                    continue
                historical_heads = {
                    str(row["head_sha"])
                    for row in state.connection.execute(
                        """
                        SELECT DISTINCT head_sha FROM scan_results
                        WHERE repository_id=?
                        """,
                        (item.node_id,),
                    )
                }
                matching_heads = sorted(
                    head_sha for head_sha in historical_heads
                    if deferred_task_key(head_sha) == proof["task_key"]
                )
                if len(matching_heads) != 1:
                    raise PipelineError(
                        "Phase 8 deferred scan-bound head changed"
                    )
                pinned_head = matching_heads[0]
            pinned[name] = dataclasses.replace(item, head_oid=pinned_head)
            state.connection.execute(
                "UPDATE repositories SET head_sha=? WHERE node_id=?",
                (pinned_head, item.node_id),
            )
        if control_head_pins and matched_control_pins != set(
            head_pin_by_identity
        ):
            raise PipelineError(
                "Phase 8 deferred scan-bound identity changed"
            )
    state.connection.commit()
    return pinned


def _validate_historical_scan_usage(
    value: Any,
) -> dict[str, Any]:
    """Validate one immutable, owner-reviewed predecessor scan charge.

    The successor builder owns the proof-row schema and aggregate
    reconstruction. Import its validator lazily to keep that logic singular:
    successor imports this module for the pipeline primitives it builds on.
    """
    from .successor import _validate_historical_scan_usage_contract

    try:
        return _validate_historical_scan_usage_contract(value)
    except PipelineError as exc:
        raise PipelineError(
            "reviewed historical scan usage is invalid: " + str(exc)
        ) from exc


def _historical_scan_usage_for_run(
    state: StateDB,
    run_id: str,
) -> dict[str, Any] | None:
    """Read and revalidate the immutable usage charge stored with a run."""
    row = state.connection.execute(
        "SELECT plan_json FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if row is None:
        raise PipelineError("scan usage run is unknown")
    try:
        plan = json.loads(row["plan_json"] or "{}")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "scan usage execution contract is malformed"
        ) from exc
    if not isinstance(plan, Mapping):
        raise PipelineError("scan usage run plan is malformed")
    execution = plan.get("execution_contract", {}) or {}
    if not isinstance(execution, Mapping):
        raise PipelineError(
            "scan usage execution contract is malformed"
        )
    value = execution.get("historical_scan_usage")
    if value is None:
        return None
    historical = _validate_historical_scan_usage(value)
    lineage = plan.get("successor_lineage", {}) or {}
    if not isinstance(lineage, Mapping):
        raise PipelineError("scan usage successor lineage is malformed")
    lineage_sha256 = lineage.get("historical_scan_usage_sha256")
    if lineage and lineage_sha256 != historical["contract_sha256"]:
        raise PipelineError(
            "historical scan usage lineage digest differs"
        )
    compatibility = state.connection.execute(
        """
        SELECT compatibility_json FROM run_lineage
        WHERE successor_run_id=?
        """,
        (run_id,),
    ).fetchone()
    if compatibility is not None:
        try:
            compatibility_document = json.loads(
                compatibility["compatibility_json"] or "{}"
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "historical scan usage compatibility is malformed"
            ) from exc
        if not isinstance(compatibility_document, Mapping):
            raise PipelineError(
                "historical scan usage compatibility is malformed"
            )
        compatibility_sha256 = compatibility_document.get(
            "historical_scan_usage_sha256"
        )
        if compatibility_sha256 != historical["contract_sha256"]:
            raise PipelineError(
                "historical scan usage compatibility digest differs"
            )
    return historical


def _combine_scan_attempt_usage(
    current: Mapping[str, Any],
    historical: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Combine one current ledger with one immutable historical charge."""
    if any(
        field in current for field in ("historical", "current", "combined")
    ):
        raise PipelineError(
            "current scan usage must be an uncombined durable ledger"
        )
    if current.get("usage_complete") is not True:
        raise PipelineError(
            "current scan attempt usage is incomplete"
        )
    current_attempt_count = current.get("attempt_count")
    if (
        not isinstance(current_attempt_count, int)
        or isinstance(current_attempt_count, bool)
        or current_attempt_count < 0
    ):
        raise PipelineError("current scan attempt usage is invalid")
    current_irreconstructible = current.get(
        "irreconstructible_attempt_count", 0
    )
    current_exact = current.get(
        "exact_attempt_count",
        current_attempt_count - current_irreconstructible,
    )
    current_timing_known = current.get(
        "timing_known_attempt_count", current_exact
    )
    current_timing_unknown = current.get(
        "timing_unknown_attempt_count", current_irreconstructible
    )
    if (
        any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            for value in (
                current_irreconstructible,
                current_exact,
                current_timing_known,
                current_timing_unknown,
            )
        )
        or current_exact + current_irreconstructible
        != current_attempt_count
        or current_timing_known + current_timing_unknown
        != current_attempt_count
    ):
        raise PipelineError("current scan attempt usage is invalid")
    current_status_counts = {}
    for field in (
        "complete_attempts",
        "failed_attempts",
        "interrupted_attempts",
    ):
        value = current.get(field)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise PipelineError("current scan attempt usage is invalid")
        current_status_counts[field] = value
    if sum(current_status_counts.values()) != current_attempt_count:
        raise PipelineError(
            "current scan attempt status counts are inconsistent"
        )
    for field in _HISTORICAL_SCAN_TIMING_FIELDS:
        value = current.get(field)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or value < 0
        ):
            raise PipelineError("current scan attempt usage is invalid")
    for field in (
        "git_subprocess_count",
        "network_clone_count",
        "network_fetch_count",
        "network_materialized_bytes",
        "git_subprocess_unknown_attempt_count",
        "network_clone_unknown_attempt_count",
        "network_fetch_unknown_attempt_count",
        "network_materialized_bytes_unknown_attempt_count",
    ):
        value = current.get(field, 0)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise PipelineError("current scan attempt usage is invalid")

    if historical is None:
        historical_summary = {
            "attempt_count": 0,
            "exact_attempt_count": 0,
            "conservative_attempt_count": 0,
            "irreconstructible_attempt_count": 0,
            "timing_known_attempt_count": 0,
            "timing_unknown_attempt_count": 0,
            "usage": {
                **{
                    field: 0.0
                    for field in _HISTORICAL_SCAN_TIMING_FIELDS
                },
                **{
                    field: 0
                    for field in _HISTORICAL_SCAN_COUNT_FIELDS
                },
            },
            "contract_sha256": None,
            "predecessor_run_id": None,
        }
    else:
        historical = _validate_historical_scan_usage(historical)
        historical_summary = {
            key: copy.deepcopy(historical[key])
            for key in (
                "predecessor_run_id",
                "predecessor_plan_sha256",
                "predecessor_lineage_sha256",
                "attempt_count",
                "exact_attempt_count",
                "conservative_attempt_count",
                "timing_known_attempt_count",
                "timing_unknown_attempt_count",
                "usage",
                "proof_rows_sha256",
                "contract_sha256",
            )
        }
        historical_summary["irreconstructible_attempt_count"] = int(
            historical.get("irreconstructible_attempt_count", 0)
        )
    historical_usage = historical_summary["usage"]
    combined = {
        "attempt_count": (
            int(historical_summary["attempt_count"])
            + current_attempt_count
        ),
        "exact_attempt_count": (
            int(historical_summary["exact_attempt_count"])
            + current_exact
        ),
        "conservative_attempt_count": int(
            historical_summary["conservative_attempt_count"]
        ),
        "irreconstructible_attempt_count": int(
            historical_summary.get("irreconstructible_attempt_count", 0)
        ) + current_irreconstructible,
        "timing_known_attempt_count": (
            int(historical_summary["timing_known_attempt_count"])
            + current_timing_known
        ),
        "timing_unknown_attempt_count": (
            int(historical_summary["timing_unknown_attempt_count"])
            + current_timing_unknown
        ),
        "git_subprocess_unknown_attempt_count": int(
            historical_usage["git_subprocess_unknown_attempt_count"]
        ) + int(current.get("git_subprocess_unknown_attempt_count", 0)),
        "network_clone_unknown_attempt_count": int(
            historical_usage["network_clone_unknown_attempt_count"]
        ) + int(current.get("network_clone_unknown_attempt_count", 0)),
        "network_fetch_unknown_attempt_count": int(
            historical_usage["network_fetch_unknown_attempt_count"]
        ) + int(current.get("network_fetch_unknown_attempt_count", 0)),
        "network_materialized_bytes_unknown_attempt_count": int(
            historical_usage.get(
                "network_materialized_bytes_unknown_attempt_count", 0
            )
        ) + int(
            current.get(
                "network_materialized_bytes_unknown_attempt_count", 0
            )
        ),
    }
    for field in _COMBINED_SCAN_USAGE_FIELDS:
        combined[field] = (
            historical_usage[field] + current[field]
        )
    result = dict(current)
    result.update(combined)
    result["historical"] = historical_summary
    result["current"] = copy.deepcopy(dict(current))
    result["combined"] = copy.deepcopy(combined)
    return result


def _scan_attempt_usage_for_run(
    state: StateDB,
    run_id: str,
) -> dict[str, Any]:
    """Combine current durable rows with historical usage exactly once."""
    current = state.scan_attempt_usage(run_id)
    historical = _historical_scan_usage_for_run(state, run_id)
    return _combine_scan_attempt_usage(current, historical)


def _enforce_scan_attempt_budgets(
    usage: Mapping[str, Any],
    *,
    planned_attempts: int,
    budgets: "RunBudgets",
) -> None:
    if (
        not isinstance(planned_attempts, int)
        or isinstance(planned_attempts, bool)
        or planned_attempts < 0
    ):
        raise PipelineError("planned scan attempt count is invalid")
    prior_attempts = usage.get("attempt_count")
    materialized_bytes = usage.get("network_materialized_bytes")
    if (
        not isinstance(prior_attempts, int)
        or isinstance(prior_attempts, bool)
        or prior_attempts < 0
        or not isinstance(materialized_bytes, int)
        or isinstance(materialized_bytes, bool)
        or materialized_bytes < 0
    ):
        raise PipelineError("combined scan attempt usage is invalid")
    if prior_attempts + planned_attempts > budgets.max_fetches:
        raise BudgetExceeded(
            "scan dispatch-attempt plan exceeds fetch budget "
            "(%d prior + %d selected > %d)"
            % (
                prior_attempts,
                planned_attempts,
                budgets.max_fetches,
            )
        )
    if materialized_bytes > budgets.max_git_materialized_bytes:
        raise BudgetExceeded(
            "prior scan attempts already exceed the Git "
            "materialization byte budget (%d > %d)"
            % (
                materialized_bytes,
                budgets.max_git_materialized_bytes,
            )
        )


def _validate_reviewed_execution_contract(
    contract: Mapping[str, Any] | None,
    *,
    mode: str,
    wanted: set[str],
    budgets: "RunBudgets",
    metadata_batch_size: int,
) -> dict[str, Any] | None:
    """Validate the immutable owner-reviewed partial-cohort control plane."""
    if contract is None:
        return None
    if not isinstance(contract, Mapping):
        raise PipelineError("reviewed execution contract must be an object")
    allowed_keys = {
        "mode",
        "run_class",
        "release_scope",
        "release_label",
        "selected_library_ids",
        "excluded_library_ids",
        "metadata_batch_size",
        "network_task_source_sha256",
        "historical_network_request_attempts",
        "historical_scan_usage",
        "historical_graphql_usage",
        "historical_wall_seconds",
        "reviewed_slo",
    }
    optional_keys = {
        "preseeded_metadata_epoch",
        "certified_scan_checkpoint",
        "wall_extension",
        "filter_extension",
        "scanner_source_migration",
        "scanner_resume_control",
        "scan_tail_deferral",
        "scan_tail_resume_control",
        "downstream_resume_control",
        "visibility_resume_control",
        "graphql_resume_control",
        "privacy_resume_control",
        "fresh_candidate_deferral_control",
        "visibility_set_resume_control",
        "visibility_rejection_resume_control",
        "visibility_refresh_resume_control",
        "visibility_budget_resume_control",
        "visibility_transport_retry_control",
        "visibility_epoch_recovery_control",
        "post_refresh_privacy_control",
        "final_visibility_privacy_control",
    }
    if (
        not allowed_keys <= set(contract)
        or set(contract) - allowed_keys - optional_keys
    ):
        raise PipelineError(
            "reviewed Phase 8 cohort execution contract shape changed"
        )
    scan_tail_deferral = contract.get("scan_tail_deferral")
    validated_deferral = None
    validated_tail_resume = None
    validated_downstream_resume = None
    validated_visibility_resume = None
    validated_graphql_resume = None
    validated_privacy_resume = None
    validated_fresh_candidate_deferral = None
    validated_visibility_set_resume = None
    validated_visibility_rejection_resume = None
    validated_visibility_refresh_resume = None
    validated_visibility_budget_resume = None
    validated_visibility_transport_retry = None
    validated_visibility_epoch_recovery = None
    validated_post_refresh_privacy = None
    validated_final_visibility_privacy = None
    if (
        scan_tail_deferral is None
        and (
            contract.get("scan_tail_resume_control") is not None
            or contract.get("downstream_resume_control") is not None
            or contract.get("visibility_resume_control") is not None
            or contract.get("graphql_resume_control") is not None
            or contract.get("privacy_resume_control") is not None
            or contract.get("fresh_candidate_deferral_control") is not None
            or contract.get("visibility_set_resume_control") is not None
            or contract.get("visibility_rejection_resume_control") is not None
            or contract.get("visibility_refresh_resume_control") is not None
            or contract.get("visibility_budget_resume_control") is not None
            or contract.get("visibility_transport_retry_control") is not None
            or contract.get("visibility_epoch_recovery_control") is not None
            or contract.get("post_refresh_privacy_control") is not None
            or contract.get("final_visibility_privacy_control") is not None
        )
    ):
        raise PipelineError(
            "Phase 8 scan-tail resume control has no deferral certificate"
        )
    if scan_tail_deferral is not None:
        validated_deferral = _validate_phase8_scan_tail_deferral(
            scan_tail_deferral
        )
        if contract.get("scan_tail_resume_control") is not None:
            validated_tail_resume = (
                _validate_phase8_scan_tail_resume_control(
                    contract["scan_tail_resume_control"],
                    validated_deferral,
                )
            )
        if contract.get("downstream_resume_control") is not None:
            if validated_tail_resume is None:
                raise PipelineError(
                    "Phase 8 downstream resume has no tail-resume certificate"
                )
            validated_downstream_resume = (
                _validate_phase8_downstream_resume_control(
                    contract["downstream_resume_control"],
                    validated_tail_resume,
                )
            )
        if contract.get("visibility_resume_control") is not None:
            if validated_downstream_resume is None:
                raise PipelineError(
                    "Phase 8 visibility resume has no downstream certificate"
                )
            validated_visibility_resume = (
                _validate_phase8_visibility_resume_control(
                    contract["visibility_resume_control"],
                    validated_downstream_resume,
                )
            )
        if contract.get("graphql_resume_control") is not None:
            if validated_visibility_resume is None:
                raise PipelineError(
                    "Phase 8 GraphQL resume has no visibility certificate"
                )
            validated_graphql_resume = (
                _validate_phase8_graphql_resume_control(
                    contract["graphql_resume_control"],
                    validated_visibility_resume,
                )
            )
        if contract.get("privacy_resume_control") is not None:
            if validated_graphql_resume is None:
                raise PipelineError(
                    "Phase 8 privacy resume has no GraphQL certificate"
                )
            validated_privacy_resume = _validate_phase8_privacy_resume_control(
                contract["privacy_resume_control"],
                validated_graphql_resume,
            )
        if contract.get("fresh_candidate_deferral_control") is not None:
            if validated_privacy_resume is None:
                raise PipelineError(
                    "Phase 8 fresh-candidate deferral has no privacy "
                    "certificate"
                )
            validated_fresh_candidate_deferral = (
                _validate_phase8_fresh_candidate_deferral_control(
                    contract["fresh_candidate_deferral_control"],
                    validated_privacy_resume,
                )
            )
        if contract.get("visibility_set_resume_control") is not None:
            if validated_fresh_candidate_deferral is None:
                raise PipelineError(
                    "Phase 8 visibility-set resume has no fresh-candidate "
                    "certificate"
                )
            validated_visibility_set_resume = (
                _validate_phase8_visibility_set_resume_control(
                    contract["visibility_set_resume_control"],
                    validated_fresh_candidate_deferral,
                )
            )
        if contract.get("visibility_rejection_resume_control") is not None:
            if validated_visibility_set_resume is None:
                raise PipelineError(
                    "Phase 8 visibility-rejection resume has no "
                    "visibility-set certificate"
                )
            validated_visibility_rejection_resume = (
                _validate_phase8_visibility_rejection_resume_control(
                    contract["visibility_rejection_resume_control"],
                    validated_visibility_set_resume,
                )
            )
        if contract.get("visibility_refresh_resume_control") is not None:
            if validated_visibility_rejection_resume is None:
                raise PipelineError(
                    "Phase 8 visibility-refresh resume has no "
                    "visibility-rejection certificate"
                )
            validated_visibility_refresh_resume = (
                _validate_phase8_visibility_refresh_resume_control(
                    contract["visibility_refresh_resume_control"],
                    validated_visibility_rejection_resume,
                )
            )
        if contract.get("visibility_budget_resume_control") is not None:
            if validated_visibility_refresh_resume is None:
                raise PipelineError(
                    "Phase 8 visibility-budget resume has no "
                    "visibility-refresh certificate"
                )
            validated_visibility_budget_resume = (
                _validate_phase8_visibility_budget_resume_control(
                    contract["visibility_budget_resume_control"],
                    validated_visibility_refresh_resume,
                )
            )
        if contract.get("visibility_transport_retry_control") is not None:
            if validated_visibility_budget_resume is None:
                raise PipelineError(
                    "Phase 8 visibility transport retry has no "
                    "visibility-budget certificate"
                )
            validated_visibility_transport_retry = (
                _validate_phase8_visibility_transport_retry_control(
                    contract["visibility_transport_retry_control"],
                    validated_visibility_budget_resume,
                )
            )
        if contract.get("visibility_epoch_recovery_control") is not None:
            if validated_visibility_transport_retry is None:
                raise PipelineError(
                    "Phase 8 visibility epoch recovery has no transport "
                    "retry certificate"
                )
            validated_visibility_epoch_recovery = (
                _validate_phase8_visibility_epoch_recovery_control(
                    contract["visibility_epoch_recovery_control"],
                    validated_visibility_transport_retry,
                )
            )
        if contract.get("post_refresh_privacy_control") is not None:
            if (
                validated_privacy_resume is None
                or validated_visibility_epoch_recovery is None
            ):
                raise PipelineError(
                    "Phase 8 post-refresh privacy has no privacy/epoch "
                    "certificates"
                )
            validated_post_refresh_privacy = (
                _validate_phase8_post_refresh_privacy_control(
                    contract["post_refresh_privacy_control"],
                    validated_privacy_resume,
                    validated_visibility_epoch_recovery,
                )
            )
        if contract.get("final_visibility_privacy_control") is not None:
            if validated_post_refresh_privacy is None:
                raise PipelineError(
                    "Phase 8 final-visibility privacy has no post-refresh "
                    "privacy certificate"
                )
            validated_final_visibility_privacy = (
                _validate_phase8_final_visibility_privacy_control(
                    contract["final_visibility_privacy_control"],
                    validated_post_refresh_privacy,
                )
            )
        expected_deferral_successor = (
            validated_tail_resume["prior_network_task_source_sha256"]
            if validated_tail_resume is not None
            else contract.get("network_task_source_sha256")
        )
        if (
            validated_deferral["current_network_task_source_sha256"]
            != expected_deferral_successor
            or (
                validated_tail_resume is not None
                and validated_tail_resume[
                    "current_network_task_source_sha256"
                ]
                != (
                    validated_downstream_resume[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_downstream_resume is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_downstream_resume is not None
                and validated_downstream_resume[
                    "current_network_task_source_sha256"
                ]
                != (
                    validated_visibility_resume[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_visibility_resume is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_visibility_resume is not None
                and validated_visibility_resume[
                    "current_network_task_source_sha256"
                ]
                != (
                    validated_graphql_resume[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_graphql_resume is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_graphql_resume is not None
                and validated_graphql_resume[
                    "current_network_task_source_sha256"
                ]
                != (
                    validated_privacy_resume[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_privacy_resume is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_privacy_resume is not None
                and validated_privacy_resume[
                    "current_network_task_source_sha256"
                ]
                != (
                    validated_fresh_candidate_deferral[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_fresh_candidate_deferral is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_fresh_candidate_deferral is not None
                and validated_fresh_candidate_deferral[
                    "current_network_task_source_sha256"
                ]
                != (
                    validated_visibility_set_resume[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_visibility_set_resume is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_visibility_set_resume is not None
                and validated_visibility_set_resume[
                    "current_network_task_source_sha256"
                ] != (
                    validated_visibility_rejection_resume[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_visibility_rejection_resume is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_visibility_rejection_resume is not None
                and validated_visibility_rejection_resume[
                    "current_network_task_source_sha256"
                ] != (
                    validated_visibility_refresh_resume[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_visibility_refresh_resume is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_visibility_refresh_resume is not None
                and validated_visibility_refresh_resume[
                    "current_network_task_source_sha256"
                ] != (
                    validated_visibility_budget_resume[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_visibility_budget_resume is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_visibility_budget_resume is not None
                and validated_visibility_budget_resume[
                    "current_network_task_source_sha256"
                ] != (
                    validated_visibility_transport_retry[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_visibility_transport_retry is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_visibility_transport_retry is not None
                and validated_visibility_transport_retry[
                    "current_network_task_source_sha256"
                ] != (
                    validated_visibility_epoch_recovery[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_visibility_epoch_recovery is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_visibility_epoch_recovery is not None
                and validated_visibility_epoch_recovery[
                    "current_network_task_source_sha256"
                ] != (
                    validated_post_refresh_privacy[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_post_refresh_privacy is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_post_refresh_privacy is not None
                and validated_post_refresh_privacy[
                    "current_network_task_source_sha256"
                ] != (
                    validated_final_visibility_privacy[
                        "prior_network_task_source_sha256"
                    ]
                    if validated_final_visibility_privacy is not None
                    else contract.get("network_task_source_sha256")
                )
            )
            or (
                validated_final_visibility_privacy is not None
                and validated_final_visibility_privacy[
                    "current_network_task_source_sha256"
                ] != contract.get("network_task_source_sha256")
            )
        ):
            raise PipelineError(
                "Phase 8 scan-tail source identity does not match this run"
            )
    active_ids = {library["id"] for library in config.LIBRARIES}
    selected = contract.get("selected_library_ids")
    excluded = contract.get("excluded_library_ids")
    if (
        mode != "reconcile"
        or not wanted
        or contract.get("mode") != "reconcile"
        or contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("release_label") != "Phase 8 Cohort A"
        or selected != sorted(wanted)
        or excluded != sorted(active_ids - wanted)
        or set(selected or ()) | set(excluded or ()) != active_ids
        or set(selected or ()) & set(excluded or ())
    ):
        raise PipelineError(
            "reviewed Phase 8 cohort scope does not match this run"
        )
    baseline_budgets = RunBudgets.reconcile().to_dict()
    actual_budgets = budgets.to_dict()
    wall_extension = contract.get("wall_extension")
    if wall_extension is None:
        if actual_budgets != baseline_budgets:
            raise PipelineError(
                "reviewed Phase 8 cohort hard budgets changed"
            )
    else:
        if (
            not isinstance(wall_extension, Mapping)
            or set(wall_extension) != {
                "version",
                "original_limit_seconds",
                "extended_limit_seconds",
                "reason",
                "authorized_at",
                "predecessor_source_commit",
                "successor_source_commit",
                "source_audit_sha256",
                "unchanged_budgets_sha256",
                "prior_historical_wall_seconds",
                "pre_extension_run_elapsed_seconds",
                "charged_wall_seconds",
            }
            or wall_extension.get("version") != 1
            or wall_extension.get("original_limit_seconds")
            != baseline_budgets["max_wall_seconds"]
            or wall_extension.get("extended_limit_seconds")
            != actual_budgets["max_wall_seconds"]
            or not (
                baseline_budgets["max_wall_seconds"]
                < actual_budgets["max_wall_seconds"]
                <= PHASE8_MAX_OWNER_WALL_SECONDS
            )
            or not isinstance(wall_extension.get("reason"), str)
            or not re.fullmatch(
                r"[a-z0-9][a-z0-9_.:-]{0,127}",
                wall_extension["reason"],
            )
            or not isinstance(wall_extension.get("authorized_at"), str)
            or any(
                not isinstance(wall_extension.get(field), (int, float))
                or isinstance(wall_extension.get(field), bool)
                or wall_extension[field] < 0
                for field in (
                    "prior_historical_wall_seconds",
                    "pre_extension_run_elapsed_seconds",
                    "charged_wall_seconds",
                )
            )
            or abs(
                wall_extension["charged_wall_seconds"]
                - (
                    wall_extension["prior_historical_wall_seconds"]
                    + wall_extension[
                        "pre_extension_run_elapsed_seconds"
                    ]
                )
            ) > 0.001
            or contract.get("historical_wall_seconds")
            != wall_extension["charged_wall_seconds"]
            or wall_extension["charged_wall_seconds"]
            >= actual_budgets["max_wall_seconds"]
            or any(
                not isinstance(wall_extension.get(field), str)
                or not re.fullmatch(r"[0-9a-f]{40,64}", wall_extension[field])
                for field in (
                    "predecessor_source_commit",
                    "successor_source_commit",
                    "source_audit_sha256",
                    "unchanged_budgets_sha256",
                )
            )
        ):
            raise PipelineError(
                "reviewed Phase 8 wall extension is invalid"
            )
        unchanged_actual = dict(actual_budgets)
        unchanged_actual.pop("max_wall_seconds")
        unchanged_baseline = dict(baseline_budgets)
        unchanged_baseline.pop("max_wall_seconds")
        if unchanged_actual != unchanged_baseline:
            raise PipelineError(
                "reviewed Phase 8 wall extension changed another budget"
            )
        expected_unchanged_sha256 = hashlib.sha256(
            fingerprint_json(unchanged_actual).encode("utf-8")
        ).hexdigest()
        if (
            wall_extension["unchanged_budgets_sha256"]
            != expected_unchanged_sha256
        ):
            raise PipelineError(
                "reviewed Phase 8 wall extension budget proof changed"
            )
    current_network_task_source = _network_task_source_sha256()
    scanner_resume_network_source = (
        validated_deferral["prior_network_task_source_sha256"]
        if validated_deferral is not None
        else current_network_task_source
    )
    scanner_source_migration = contract.get("scanner_source_migration")
    scanner_resume_control = contract.get("scanner_resume_control")
    reviewed_scanner_network_source = current_network_task_source
    if scanner_resume_control is not None:
        expected_resume_control_keys = {
            "version",
            "kind",
            "policy",
            "predecessor_source_commit",
            "successor_source_commit",
            "required_control_commits",
            "changed_paths",
            "source_audit_sha256",
            "prior_fingerprints_sha256",
            "current_fingerprints_sha256",
            "prior_network_task_source_sha256",
            "current_network_task_source_sha256",
            "scanner_migration_contract_sha256",
            "task_universe_count",
            "completed_scan_task_count",
            "failed_scan_task_count",
            "pending_scan_task_count",
            "running_scan_task_count",
            "scan_attempt_count",
            "scan_result_count",
            "preserved_state_sha256",
            "contract_sha256",
        }
        expected_resume_paths = {
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
        }
        expected_resume_commits = [
            "3ffc6eb48d33040ea6e218499a89444f75050997",
            "6b9528d7f6c5f2506ecee15f18bde56a81886bff",
        ]
        current_fingerprint_sha256 = hashlib.sha256(
            fingerprint_json(current_fingerprints().as_dict()).encode("utf-8")
        ).hexdigest()
        if not isinstance(scanner_resume_control, Mapping):
            raise PipelineError(
                "reviewed Phase 8 scanner resume control is invalid"
            )
        scanner_resume_control = dict(scanner_resume_control)
        resume_document = dict(scanner_resume_control)
        resume_sha256 = resume_document.pop("contract_sha256", None)
        resume_counts = tuple(
            scanner_resume_control.get(field)
            for field in (
                "completed_scan_task_count",
                "failed_scan_task_count",
                "pending_scan_task_count",
                "running_scan_task_count",
            )
        )
        if (
            set(scanner_resume_control) != expected_resume_control_keys
            or scanner_resume_control.get("version") != 1
            or scanner_resume_control.get("kind")
            != "phase8-audited-scanner-resume-control"
            or scanner_resume_control.get("policy")
            != "source-only-durable-status-partition"
            or scanner_resume_control.get("predecessor_source_commit")
            != "3c40267b9844a84aa6d08c2f6a897c81a950fcb4"
            or scanner_resume_control.get("required_control_commits")
            != expected_resume_commits
            or set(scanner_resume_control.get("changed_paths") or ())
            != expected_resume_paths
            or scanner_resume_control.get("changed_paths")
            != sorted(expected_resume_paths)
            or scanner_source_migration is None
            or not isinstance(scanner_source_migration, Mapping)
            or scanner_resume_control.get(
                "scanner_migration_contract_sha256"
            ) != scanner_source_migration.get("contract_sha256")
            or scanner_resume_control.get(
                "prior_network_task_source_sha256"
            ) != scanner_source_migration.get(
                "current_network_task_source_sha256"
            )
            or scanner_resume_control.get(
                "current_network_task_source_sha256"
            ) != scanner_resume_network_source
            or scanner_resume_control.get(
                "prior_network_task_source_sha256"
            ) == scanner_resume_network_source
            or scanner_resume_control.get("prior_fingerprints_sha256")
            != current_fingerprint_sha256
            or scanner_resume_control.get("current_fingerprints_sha256")
            != current_fingerprint_sha256
            or scanner_resume_control.get("task_universe_count") != 38321
            or len(resume_counts) != 4
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in resume_counts
            )
            or sum(resume_counts) != 38321
            or scanner_resume_control.get("completed_scan_task_count") < 1
            or scanner_resume_control.get("running_scan_task_count") != 0
            or any(
                not isinstance(scanner_resume_control.get(field), int)
                or isinstance(scanner_resume_control.get(field), bool)
                or scanner_resume_control[field] < 0
                for field in ("scan_attempt_count", "scan_result_count")
            )
            or any(
                not isinstance(scanner_resume_control.get(field), str)
                or not re.fullmatch(
                    r"[0-9a-f]{64}", scanner_resume_control[field]
                )
                for field in (
                    "source_audit_sha256",
                    "prior_fingerprints_sha256",
                    "current_fingerprints_sha256",
                    "prior_network_task_source_sha256",
                    "current_network_task_source_sha256",
                    "scanner_migration_contract_sha256",
                    "preserved_state_sha256",
                    "contract_sha256",
                )
            )
            or not isinstance(
                scanner_resume_control.get("successor_source_commit"), str
            )
            or not re.fullmatch(
                r"[0-9a-f]{40}",
                scanner_resume_control["successor_source_commit"],
            )
            or hashlib.sha256(
                fingerprint_json(resume_document).encode("utf-8")
            ).hexdigest() != resume_sha256
        ):
            raise PipelineError(
                "reviewed Phase 8 scanner resume control is invalid"
            )
        reviewed_scanner_network_source = scanner_resume_control[
            "prior_network_task_source_sha256"
        ]
    migration_prior_shared_filter = None
    if scanner_source_migration is not None:
        expected_migration_keys = {
            "version",
            "kind",
            "policy",
            "predecessor_source_commit",
            "audited_issue_commit",
            "successor_source_commit",
            "changed_issue_paths",
            "changed_control_paths",
            "source_audit_sha256",
            "prior_fingerprints_sha256",
            "current_fingerprints_sha256",
            "prior_shared_filter_sha256",
            "current_shared_filter_sha256",
            "prior_network_task_source_sha256",
            "current_network_task_source_sha256",
            "task_universe_count",
            "completed_scan_tasks_certified",
            "completed_result_documents_sha256",
            "completed_results_with_virtual_documents_evidence",
            "certified_checkpoint_scan_result_count",
            "certified_checkpoint_repository_count",
            "certified_checkpoint_certificate_sha256",
            "migrated_scan_result_count",
            "migrated_repository_count",
            "migrated_scan_results_sha256",
            "migrated_scan_task_key_count",
            "migrated_scan_task_keys_sha256",
            "target_detector_fingerprints_sha256",
            "contract_sha256",
        }
        if not isinstance(scanner_source_migration, Mapping):
            raise PipelineError(
                "reviewed Phase 8 scanner source migration is invalid"
            )
        scanner_source_migration = dict(scanner_source_migration)
        migration_document = dict(scanner_source_migration)
        migration_sha256 = migration_document.pop("contract_sha256", None)
        current_fingerprint_document = current_fingerprints().as_dict()
        current_fingerprint_sha256 = hashlib.sha256(
            fingerprint_json(current_fingerprint_document).encode("utf-8")
        ).hexdigest()
        if (
            set(scanner_source_migration) != expected_migration_keys
            or scanner_source_migration.get("version") != 1
            or scanner_source_migration.get("kind")
            != "phase8-audited-scanner-source-compatibility-migration"
            or scanner_source_migration.get("policy")
            != "exact-source-monotonic-result-preservation"
            or scanner_source_migration.get("current_fingerprints_sha256")
            != current_fingerprint_sha256
            or scanner_source_migration.get("current_shared_filter_sha256")
            != current_fingerprint_document["filters"]["shared"]
            or scanner_source_migration.get("prior_shared_filter_sha256")
            == current_fingerprint_document["filters"]["shared"]
            or scanner_source_migration.get(
                "current_network_task_source_sha256"
            ) != reviewed_scanner_network_source
            or scanner_source_migration.get(
                "prior_network_task_source_sha256"
            ) == reviewed_scanner_network_source
            or scanner_source_migration.get("predecessor_source_commit")
            != "aafdc5e14d6b814b5e53e59f266c485bdffc586b"
            or scanner_source_migration.get("audited_issue_commit")
            != "b1e69e56ef030623848dbac351d06d0bd833209f"
            or set(scanner_source_migration.get("changed_issue_paths") or ())
            != {
                "collector/config.py",
                "collector/repo_cache.py",
                "collector/scan.py",
                "test_req14_content_materialization.py",
                "test_req14_scanner.py",
            }
            or set(scanner_source_migration.get("changed_control_paths") or ())
            - {
                "collector/cli.py",
                "collector/phase8_source_migration.py",
                "collector/pipeline.py",
                "ops/req14_detector_fingerprints.json",
                "test_req14_pipeline.py",
            }
            or scanner_source_migration.get(
                "completed_results_with_virtual_documents_evidence"
            ) != 0
            or scanner_source_migration.get("task_universe_count") != 38321
            or scanner_source_migration.get("migrated_scan_task_key_count")
            != 38321
            or any(
                not isinstance(scanner_source_migration.get(field), int)
                or isinstance(scanner_source_migration.get(field), bool)
                or scanner_source_migration[field] < minimum
                for field, minimum in (
                    ("task_universe_count", 1),
                    ("completed_scan_tasks_certified", 1),
                    ("certified_checkpoint_scan_result_count", 0),
                    ("certified_checkpoint_repository_count", 0),
                    ("migrated_scan_result_count", 1),
                    ("migrated_repository_count", 1),
                    ("migrated_scan_task_key_count", 1),
                )
            )
            or any(
                not isinstance(scanner_source_migration.get(field), str)
                or not re.fullmatch(
                    r"[0-9a-f]{64}", scanner_source_migration[field]
                )
                for field in (
                    "source_audit_sha256",
                    "prior_fingerprints_sha256",
                    "current_fingerprints_sha256",
                    "prior_shared_filter_sha256",
                    "current_shared_filter_sha256",
                    "prior_network_task_source_sha256",
                    "current_network_task_source_sha256",
                    "completed_result_documents_sha256",
                    "certified_checkpoint_certificate_sha256",
                    "migrated_scan_results_sha256",
                    "migrated_scan_task_keys_sha256",
                    "target_detector_fingerprints_sha256",
                    "contract_sha256",
                )
            )
            or any(
                not isinstance(scanner_source_migration.get(field), str)
                or not re.fullmatch(
                    r"[0-9a-f]{40}", scanner_source_migration[field]
                )
                for field in (
                    "predecessor_source_commit",
                    "audited_issue_commit",
                    "successor_source_commit",
                )
            )
            or not isinstance(
                scanner_source_migration.get("changed_issue_paths"), list
            )
            or not scanner_source_migration["changed_issue_paths"]
            or scanner_source_migration["changed_issue_paths"]
            != sorted(set(scanner_source_migration["changed_issue_paths"]))
            or not isinstance(
                scanner_source_migration.get("changed_control_paths"), list
            )
            or not scanner_source_migration["changed_control_paths"]
            or scanner_source_migration["changed_control_paths"]
            != sorted(set(scanner_source_migration["changed_control_paths"]))
            or hashlib.sha256(
                fingerprint_json(migration_document).encode("utf-8")
            ).hexdigest() != migration_sha256
        ):
            raise PipelineError(
                "reviewed Phase 8 scanner source migration is invalid"
            )
        migration_prior_shared_filter = scanner_source_migration[
            "prior_shared_filter_sha256"
        ]

    filter_extension = contract.get("filter_extension")
    if filter_extension is not None:
        expected_filter_keys = {
            "version",
            "kind",
            "directory_segment",
            "policy",
            "prior_shared_filter_sha256",
            "current_shared_filter_sha256",
            "source_proof_sha256",
            "completed_scan_tasks_certified",
            "completed_result_documents_sha256",
            "completed_results_with_buildozer_evidence",
            "certified_checkpoint_scan_result_count",
            "certified_checkpoint_repository_count",
            "certified_checkpoint_certificate_sha256",
            "migrated_scan_result_count",
            "migrated_repository_count",
            "migrated_scan_results_sha256",
            "migrated_scan_task_key_count",
            "migrated_scan_task_keys_sha256",
            "target_detector_fingerprints_sha256",
            "incident_task_id",
            "incident_prior_task_key",
            "incident_task_key",
            "incident_repository_id",
            "incident_full_name",
            "incident_head_sha",
            "incident_prior_attempts",
            "tracked_buildozer_path_count",
            "tracked_buildozer_paths_sha256",
            "case_collision_count",
            "case_collisions_sha256",
            "contract_sha256",
        }
        if not isinstance(filter_extension, Mapping):
            raise PipelineError("reviewed Phase 8 filter extension is invalid")
        filter_extension = dict(filter_extension)
        proof_document = dict(filter_extension)
        proof_sha256 = proof_document.pop("contract_sha256", None)
        current_shared_filter = (
            migration_prior_shared_filter
            or current_fingerprints().filters.get("shared")
        )
        if (
            set(filter_extension) != expected_filter_keys
            or filter_extension.get("version") != 1
            or filter_extension.get("kind")
            != "phase8-exact-buildozer-generated-output-filter-extension"
            or filter_extension.get("directory_segment") != ".buildozer"
            or filter_extension.get("policy")
            != "monotonic-exclusion-certified-result-migration"
            or filter_extension.get("current_shared_filter_sha256")
            != current_shared_filter
            or filter_extension.get("prior_shared_filter_sha256")
            == current_shared_filter
            or filter_extension.get(
                "completed_results_with_buildozer_evidence"
            ) != 0
            or filter_extension.get("incident_full_name")
            != "Silian1234/shootAnalyzer"
            or any(
                not isinstance(filter_extension.get(field), int)
                or isinstance(filter_extension.get(field), bool)
                or filter_extension[field] < minimum
                for field, minimum in (
                    ("completed_scan_tasks_certified", 0),
                    ("certified_checkpoint_scan_result_count", 0),
                    ("certified_checkpoint_repository_count", 0),
                    ("migrated_scan_result_count", 1),
                    ("migrated_repository_count", 1),
                    ("migrated_scan_task_key_count", 1),
                    ("incident_task_id", 1),
                    ("incident_prior_attempts", 1),
                    ("tracked_buildozer_path_count", 1),
                    ("case_collision_count", 1),
                )
            )
            or any(
                not isinstance(filter_extension.get(field), str)
                or not re.fullmatch(r"[0-9a-f]{64}", filter_extension[field])
                for field in (
                    "prior_shared_filter_sha256",
                    "current_shared_filter_sha256",
                    "source_proof_sha256",
                    "completed_result_documents_sha256",
                    "certified_checkpoint_certificate_sha256",
                    "migrated_scan_results_sha256",
                    "migrated_scan_task_keys_sha256",
                    "target_detector_fingerprints_sha256",
                    "tracked_buildozer_paths_sha256",
                    "case_collisions_sha256",
                    "contract_sha256",
                )
            )
            or not isinstance(filter_extension.get("incident_task_key"), str)
            or not filter_extension["incident_task_key"]
            or not isinstance(
                filter_extension.get("incident_prior_task_key"), str
            )
            or not filter_extension["incident_prior_task_key"]
            or filter_extension["incident_prior_task_key"]
            == filter_extension["incident_task_key"]
            or not isinstance(
                filter_extension.get("incident_repository_id"), str
            )
            or not filter_extension["incident_repository_id"]
            or not isinstance(filter_extension.get("incident_head_sha"), str)
            or not re.fullmatch(
                r"[0-9a-f]{40,64}", filter_extension["incident_head_sha"]
            )
            or hashlib.sha256(
                fingerprint_json(proof_document).encode("utf-8")
            ).hexdigest() != proof_sha256
        ):
            raise PipelineError("reviewed Phase 8 filter extension is invalid")
    if contract.get("metadata_batch_size") != metadata_batch_size:
        raise PipelineError(
            "reviewed Phase 8 cohort metadata batch size changed"
        )
    if (
        contract.get("network_task_source_sha256")
        != current_network_task_source
    ):
        raise PipelineError(
            "reviewed Phase 8 cohort network executable changed"
        )
    historical = contract.get("historical_network_request_attempts")
    if (
        not isinstance(historical, Mapping)
        or set(historical) != {"github-code-search", "sourcegraph"}
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            for value in historical.values()
        )
    ):
        raise PipelineError(
            "reviewed Phase 8 cohort historical request usage is invalid"
        )
    try:
        historical_scan_usage = _validate_historical_scan_usage(
            contract.get("historical_scan_usage")
        )
    except PipelineError as exc:
        raise PipelineError(
            "reviewed Phase 8 cohort historical scan usage is invalid: %s"
            % exc
        ) from exc
    certified_checkpoint = contract.get("certified_scan_checkpoint")
    if certified_checkpoint is not None:
        from .successor import (
            _validate_certified_scan_checkpoint_contract,
        )
        _validate_certified_scan_checkpoint_contract(
            certified_checkpoint
        )
    if (
        historical_scan_usage.get("irreconstructible_attempt_count", 0)
        and certified_checkpoint is None
    ):
        raise PipelineError(
            "reviewed unknown scan usage lacks its checkpoint certificate"
        )
    historical_graphql = contract.get("historical_graphql_usage")
    if (
        not isinstance(historical_graphql, Mapping)
        or set(historical_graphql)
        != {"request_count", "points_used", "remaining", "reset_at"}
        or any(
            not isinstance(historical_graphql.get(field), int)
            or isinstance(historical_graphql.get(field), bool)
            or historical_graphql[field] < 0
            for field in ("request_count", "points_used")
        )
        or (
            historical_graphql.get("remaining") is not None
            and (
                not isinstance(historical_graphql["remaining"], int)
                or isinstance(historical_graphql["remaining"], bool)
                or historical_graphql["remaining"] < 0
            )
        )
        or (
            historical_graphql.get("reset_at") is not None
            and not isinstance(historical_graphql["reset_at"], str)
        )
    ):
        raise PipelineError(
            "reviewed Phase 8 cohort historical GraphQL usage is invalid"
        )
    historical_wall_seconds = contract.get("historical_wall_seconds")
    if (
        not isinstance(historical_wall_seconds, (int, float))
        or isinstance(historical_wall_seconds, bool)
        or historical_wall_seconds < 0
        or historical_wall_seconds >= budgets.max_wall_seconds
    ):
        raise PipelineError(
            "reviewed Phase 8 cohort historical wall usage is invalid"
        )
    if contract.get("reviewed_slo") != {
        "class": "partial_cohort_reconciliation",
        "target_seconds": 24 * 3600,
        "ceiling_seconds": budgets.max_wall_seconds,
    }:
        raise PipelineError("reviewed Phase 8 cohort SLO changed")
    preseeded = contract.get("preseeded_metadata_epoch")
    if preseeded is not None and (
        not isinstance(preseeded, Mapping)
        or set(preseeded)
        != {
            "task_count",
            "lookup_count",
            "task_universe_sha256",
            "result_universe_sha256",
            "input_context_sha256",
        }
        or any(
            not isinstance(preseeded.get(field), int)
            or isinstance(preseeded.get(field), bool)
            or preseeded[field] <= 0
            for field in ("task_count", "lookup_count")
        )
        or any(
            not isinstance(preseeded.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", preseeded[field])
            for field in (
                "task_universe_sha256",
                "result_universe_sha256",
                "input_context_sha256",
            )
        )
    ):
        raise PipelineError(
            "reviewed Phase 8 preseeded metadata contract is invalid"
        )
    return copy.deepcopy(dict(contract))


def _rss_usage_bytes() -> dict[str, int]:
    """Return portable, conservative peak-RSS accounting.

    macOS reports ``ru_maxrss`` in bytes while Linux reports KiB. The
    coordinator and worker-child peaks are separate observations, so summing
    them is a conservative upper bound suitable for enforcing the run budget.
    """
    multiplier = 1 if sys.platform == "darwin" else 1024
    self_bytes = int(
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * multiplier
    )
    children_bytes = int(
        resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * multiplier
    )
    return {
        "self": max(0, self_bytes),
        "children": max(0, children_bytes),
        "combined_upper": max(0, self_bytes) + max(0, children_bytes),
    }


def _scan_classification_inventory(outcomes) -> dict[str, Any]:
    """Count each evaluated repository/library verdict exactly once."""
    classifications = ("confirmed", "bundled", "targeted", "rejected")
    totals = {name: 0 for name in classifications}
    by_library: dict[str, dict[str, int]] = {}
    for outcome in outcomes:
        result = outcome.result if isinstance(outcome.result, Mapping) else {}
        rows = result.get("libraries", {})
        if not isinstance(rows, Mapping):
            rows = {}
        library_ids = {
            library_id
            for library_id in (
                tuple(outcome.candidate_library_ids)
                + tuple(outcome.triaged_library_ids)
            )
            if isinstance(library_id, str) and library_id
        }
        library_ids.update(
            library_id
            for library_id in rows
            if isinstance(library_id, str) and library_id
        )
        for library_id in sorted(library_ids):
            row = rows.get(library_id)
            classification = (
                row.get("classification")
                if isinstance(row, Mapping)
                else "rejected"
            )
            if classification not in classifications:
                raise PipelineError(
                    "scanner returned an invalid classification"
                )
            library_counts = by_library.setdefault(
                library_id,
                {name: 0 for name in classifications},
            )
            totals[classification] += 1
            library_counts[classification] += 1
    return {
        "totals": totals,
        "by_library": {
            library_id: by_library[library_id]
            for library_id in sorted(by_library)
        },
    }


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".%s.tmp-%d" % (path.name, os.getpid()))
    payload = (fingerprint_json(value) + "\n").encode("utf-8")
    with temporary.open("wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _close_and_validate_v2(root: Path) -> None:
    """Validate the selected manifest, then prune exactly to its closure."""
    from .validate_v2 import validate_v2

    errors = validate_v2(root, require_artifact_closure=False)
    if errors:
        raise PipelineError(
            "recovering V2 release is invalid:\n- " + "\n- ".join(errors)
        )
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    expected = {"manifest.json"}
    pending = [manifest]
    while pending:
        value = pending.pop()
        if isinstance(value, Mapping):
            descriptor_keys = {"path", "bytes", "sha256", "media_type"}
            if descriptor_keys.issubset(value):
                relative = value["path"]
                candidate = Path(relative) if isinstance(relative, str) else None
                if (
                    candidate is None
                    or candidate.is_absolute()
                    or ".." in candidate.parts
                ):
                    raise PipelineError("V2 recovery found an unsafe artifact path")
                rendered = candidate.as_posix()
                expected.add(rendered)
                artifact = root / candidate
                payload = artifact.read_bytes()
                if (
                    len(payload) != value["bytes"]
                    or hashlib.sha256(payload).hexdigest() != value["sha256"]
                ):
                    raise PipelineError(
                        "V2 recovery artifact does not match its descriptor"
                    )
                if value.get("media_type") == "application/json":
                    pending.append(json.loads(payload))
            else:
                pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    for relative in sorted(actual - expected):
        candidate = root / relative
        if candidate.is_file() or candidate.is_symlink():
            candidate.unlink()
    for directory in sorted(
        (path for path in root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        try:
            directory.rmdir()
        except OSError:
            pass
    closure_errors = validate_v2(root, require_artifact_closure=True)
    if closure_errors:
        raise PipelineError(
            "V2 recovery closure is invalid:\n- "
            + "\n- ".join(closure_errors)
        )


@dataclasses.dataclass(frozen=True)
class RunBudgets:
    max_wall_seconds: int
    max_scan_repositories: int
    max_sourcegraph_requests: int
    max_github_search_requests: int
    max_graphql_points: int
    min_graphql_remaining: int
    max_fetches: int
    workers: int
    max_openalex_requests: int = 2_000
    max_citation_source_extractions: int = 2_000
    # A task commits independently. Keeping the hard task deadline below ten
    # minutes also keeps worst-case crash/restart replay below the checkpoint
    # loss objective.
    repo_timeout_seconds: int = 9 * 60
    cache_target_bytes: int = 200 * 1024**3
    cache_hard_bytes: int = 250 * 1024**3
    max_git_materialized_bytes: int = 128 * 1024**3
    max_rss_bytes: int = 16 * 1024**3

    def __post_init__(self):
        positive = (
            "max_wall_seconds",
            "max_graphql_points",
            "workers",
            "repo_timeout_seconds",
            "cache_target_bytes",
            "cache_hard_bytes",
            "max_git_materialized_bytes",
            "max_rss_bytes",
        )
        nonnegative = (
            "max_scan_repositories",
            "max_sourcegraph_requests",
            "max_github_search_requests",
            "min_graphql_remaining",
            "max_fetches",
            "max_openalex_requests",
            "max_citation_source_extractions",
        )
        for field in positive:
            if getattr(self, field) <= 0:
                raise ValueError("%s must be positive" % field)
        for field in nonnegative:
            if getattr(self, field) < 0:
                raise ValueError("%s cannot be negative" % field)
        if self.cache_target_bytes > self.cache_hard_bytes:
            raise ValueError(
                "cache_target_bytes cannot exceed cache_hard_bytes"
            )

    @classmethod
    def weekly(cls):
        return cls(
            max_wall_seconds=4 * 3600,
            max_scan_repositories=2_000,
            max_sourcegraph_requests=500,
            max_github_search_requests=2_000,
            max_graphql_points=2_500,
            min_graphql_remaining=2_500,
            max_fetches=2_000,
            workers=6,
            max_openalex_requests=2_000,
            max_citation_source_extractions=2_000,
        )

    @classmethod
    def reconcile(cls):
        return cls(
            max_wall_seconds=36 * 3600,
            max_scan_repositories=60_000,
            max_sourcegraph_requests=1_000,
            max_github_search_requests=20_000,
            max_graphql_points=2_500,
            min_graphql_remaining=2_500,
            max_fetches=60_000,
            workers=14,
            max_openalex_requests=10_000,
            max_citation_source_extractions=10_000,
            max_git_materialized_bytes=2 * 1024**4,
        )

    def to_dict(self):
        return dataclasses.asdict(self)


def _catalog_index():
    return {item["id"]: item for item in CATALOG}


def _library_fp_values(plan: RunPlan, library_id: str) -> dict:
    values = plan.fingerprints.libraries[library_id]
    filter_values = {"shared": plan.fingerprints.filters["shared"]}
    if library_id == "nvpl":
        filter_values["nvpl"] = plan.fingerprints.filters["nvpl"]
    return {
        **values.as_dict(),
        # Current-tree verdict validity is independent from dating and
        # repository-wide AI enrichment. Those have separate positive-only
        # work paths below.
        "detector": fingerprint(
            "library:%s:effective-detector" % library_id,
            {
                "detector": values.detector,
                "filters": filter_values,
            },
        ),
        "dating": plan.fingerprints.dating,
        "aggregation": plan.fingerprints.aggregation,
    }


def _catalog_only_fp_values(item: Mapping[str, Any]) -> dict[str, str]:
    """Fingerprint a real catalog entity that has no executable detector."""
    value = fingerprint("catalog-only-library", dict(item))
    return {
        key: value
        for key in (
            "discovery",
            "detector",
            "citation",
            "dating",
            "aggregation",
            "presentation",
            "release",
        )
    }


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return default


def _legacy_candidates(data_dir: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    current = _load_json(data_dir / "current.json", {})
    for repo in current.get("repos", ()):
        name = repo.get("full_name")
        if not isinstance(name, str):
            continue
        for entry in repo.get("libraries", ()):
            library_id = entry.get("library_id")
            if isinstance(library_id, str):
                result[name].add(library_id)
    return result


def _repository_excluded(full_name: str) -> bool:
    """Apply the complete global repository exclusion contract."""
    return (
        full_name.casefold() in config.EXCLUDED_REPOS
        or discover._owner_excluded(
            full_name,
            config.EXCLUDED_ORGS,
            config.EXCLUDED_ORG_PREFIXES,
            config.EXCLUDED_NAME_SUBSTR,
        )
    )


def _preserve_repository_lineage(
    current: Mapping[str, Any],
    prior: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Carry forward REST-era parent/source identity without stale display data."""
    merged = dict(current)
    if not isinstance(prior, Mapping):
        return merged
    containers = [prior]
    nested = prior.get("metadata")
    if isinstance(nested, Mapping):
        containers.append(nested)
    for key in ("parent", "source"):
        if key in merged:
            continue
        for container in containers:
            if key in container:
                merged[key] = copy.deepcopy(container[key])
                break
    return merged


def _library_repository_excluded(
    full_name: str,
    library: Mapping[str, Any],
    repository_metadata: Mapping[str, Any] | None = None,
) -> bool:
    """Apply library-specific canonical-project and hand-copy exclusions.

    ``parent`` and ``source`` are retained as distinct identity signals.  They
    catch renamed forks/copies whose current name no longer resembles the
    canonical project, while name fragments remain scoped to the repository's
    current full name.  NVPL's historical profile is separate from detector
    declarations, so it is explicitly composed here at every pipeline
    boundary.
    """
    folded = full_name.casefold()
    repository_exceptions = {
        str(name).casefold()
        for name in library.get("repository_exceptions", ())
    }
    if folded in repository_exceptions:
        return False

    vendor_parents = {
        str(parent).casefold()
        for parent in library.get("vendor_parents", ())
    }
    vendor_name_substr = {
        str(fragment).casefold()
        for fragment in library.get("vendor_name_substr", ())
    }
    if library.get("id") == "nvpl" or library.get("family") == "nvpl":
        vendor_parents.update(
            str(parent).casefold()
            for parent in config.NVPL_VENDOR_PARENTS
        )
        vendor_name_substr.update(
            str(fragment).casefold()
            for fragment in config.NVPL_VENDOR_NAME_SUBSTR
        )

    def repository_name(value: Any) -> str | None:
        if isinstance(value, str):
            return value
        if isinstance(value, Mapping):
            for key in (
                "full_name",
                "fullName",
                "name_with_owner",
                "nameWithOwner",
            ):
                name = value.get(key)
                if isinstance(name, str):
                    return name
        return None

    lineage_names = []
    metadata = repository_metadata or {}
    containers = [metadata]
    nested = metadata.get("metadata")
    if isinstance(nested, Mapping):
        containers.append(nested)
    for container in containers:
        for key in ("parent", "source"):
            name = repository_name(container.get(key))
            if name:
                lineage_names.append(name.casefold())

    if folded in vendor_parents or any(
        name in vendor_parents for name in lineage_names
    ):
        return True
    return any(
        fragment in folded for fragment in vendor_name_substr
    )


def _discovery_observation_excluded(
    observation: DiscoveryObservation,
    library: Mapping[str, Any],
) -> bool:
    """Reject only a reviewed exact false-positive discovery document.

    These rules are deliberately observation-scoped rather than permanent
    repository denylists. A changed blob, path, source, or signal remains
    eligible, so future genuine adoption cannot be hidden by an old collision.
    """
    for rule in library.get("discovery_observation_exclusions", ()):
        if (
            observation.repo_full_name.casefold()
            == str(rule["repository"]).casefold()
            and observation.source == rule["source"]
            and observation.signal_id == rule["signal_id"]
            and observation.matched_path == rule["matched_path"]
            and observation.matched_blob == rule["matched_blob"]
        ):
            return True
    return False


def _state_candidates(state: StateDB) -> tuple[dict[str, set[str]], list[tuple[str, str]]]:
    by_name: dict[str, set[str]] = defaultdict(set)
    known = []
    rows = state.connection.execute(
        """
        SELECT r.node_id, r.full_name, c.library_id
        FROM repositories r
        LEFT JOIN candidates c
          ON c.repository_id=r.node_id AND c.state='active'
        ORDER BY r.full_name, c.library_id
        """
    )
    for row in rows:
        known.append((row["node_id"], row["full_name"]))
        if row["library_id"]:
            by_name[row["full_name"]].add(row["library_id"])
    return by_name, list(dict.fromkeys(known))


def _github_query_fp(pack) -> str:
    return github_query_fingerprint(pack)


def _github_lane_ids(state: StateDB, libraries, today=None):
    """Select lanes that are due, guaranteeing a complete epoch within 28 days."""
    today = today or datetime.datetime.now(datetime.timezone.utc)
    due = set()
    for lib in libraries:
        expected = {_github_query_fp(pack) for pack in query_packs(lib)}
        rows = state.connection.execute(
            """
            SELECT dc.query_fp, MAX(dc.observed_at)
            FROM discovery_coverage dc
            JOIN runs r ON r.run_id=dc.run_id
            WHERE dc.library_id=? AND dc.source='github-code-search'
              AND dc.complete=1 AND dc.capped=0 AND r.status='complete'
            GROUP BY dc.query_fp
            """,
            (lib["id"],),
        ).fetchall()
        by_query = {row[0]: row[1] for row in rows}
        if not expected.issubset(by_query):
            due.add(lib["id"])
            continue
        for stamp in (by_query[query_fp] for query_fp in expected):
            try:
                parsed = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except (AttributeError, ValueError):
                due.add(lib["id"])
                break
            if (today - parsed).days >= 21:
                due.add(lib["id"])
                break
    return due


def _carry_forward_coverage_certificates(
    state: StateDB,
    libraries: Iterable[Mapping[str, Any]],
    current: Iterable[Mapping[str, Any]],
    *,
    now: datetime.datetime | None = None,
) -> list[dict[str, Any]]:
    """Add still-current prior GitHub certificates omitted by lane rotation."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    merged = [dict(item) for item in current]
    present = {
        (
            item.get("library_id"),
            item.get("source"),
            item.get("query_fingerprint"),
        )
        for item in merged
    }
    expected = {
        (lib["id"], _github_query_fp(pack))
        for lib in libraries
        for pack in query_packs(lib)
    }
    rows = state.connection.execute(
        """
        SELECT library_id, source, query_fp, certificate_json, observed_at
        FROM (
            SELECT dc.library_id, dc.source, dc.query_fp,
                   dc.certificate_json, dc.observed_at,
                   ROW_NUMBER() OVER (
                       PARTITION BY dc.library_id, dc.source, dc.query_fp
                       ORDER BY dc.observed_at DESC, dc.run_id DESC
                   ) AS rank
            FROM discovery_coverage dc
            JOIN runs r ON r.run_id=dc.run_id
            WHERE r.status='complete' AND dc.complete=1 AND dc.capped=0
              AND dc.source='github-code-search'
        )
        WHERE rank=1
        """
    ).fetchall()
    for row in rows:
        key = (row["library_id"], row["source"], row["query_fp"])
        if (
            key in present
            or (row["library_id"], row["query_fp"]) not in expected
        ):
            continue
        try:
            certificate = json.loads(row["certificate_json"])
            observed = datetime.datetime.fromisoformat(
                str(row["observed_at"]).replace("Z", "+00:00")
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(certificate, dict):
            continue
        certificate.update(
            {
                "carried_forward": True,
                "as_of": row["observed_at"],
                "stale": (now - observed).days >= 28,
            }
        )
        merged.append(certificate)
        present.add(key)
    return merged


def _record_coverage(state: StateDB, run_id: str, result) -> None:
    certificate = result.certificate
    parts = certificate.partitions or ()
    if not parts:
        parts = (None,)
    for part in parts:
        state.record_discovery_coverage(
            run_id=run_id,
            library_id=certificate.library_id,
            source=certificate.source,
            query_fp=certificate.query_fingerprint,
            partition_key=part.key if part else "summary",
            complete=bool(certificate.complete and (part is None or part.complete)),
            result_count=part.fetched_count if part else certificate.observations_count,
            capped=bool(part and part.capped and not part.subdivided),
            lag_seconds=certificate.source_lag_max_seconds,
            gaps=[gap.to_dict() for gap in certificate.gaps],
            certificate=certificate.to_dict(),
        )


def _discovery_result_to_task_result(
    result: DiscoveryResult,
) -> dict[str, Any]:
    return {
        "version": 1,
        "kind": "discovery-query",
        "observations": [
            observation.to_dict() for observation in result.observations
        ],
        "quarantined_observations": [
            observation.to_dict()
            for observation in result.quarantined_observations
        ],
        "certificate": result.certificate.to_dict(),
    }


def _assert_discovery_task_result(
    result: DiscoveryResult,
    spec: Mapping[str, Any],
) -> None:
    certificate = result.certificate
    if (
        certificate.source != spec["source"]
        or certificate.library_id != spec["library_id"]
        or certificate.query_fingerprint
        != spec["query_fingerprint"]
    ):
        raise PipelineError(
            "discovery adapter returned the wrong query lane"
        )
    for observation in (
        tuple(result.observations)
        + tuple(result.quarantined_observations)
    ):
        if (
            observation.source != spec["source"]
            or observation.library_id != spec["library_id"]
            or observation.signal_id != spec["signal_id"]
            or observation.query_fingerprint
            != spec["query_fingerprint"]
        ):
            raise PipelineError(
                "discovery result contains cross-lane evidence"
            )


def _required_timestamp(value: Any, *, field: str) -> datetime.datetime:
    parsed = parse_timestamp(value)
    if parsed is None:
        raise PipelineError(
            "journaled discovery result has invalid %s" % field
        )
    return parsed


def _discovery_observation_from_dict(
    value: Mapping[str, Any],
) -> DiscoveryObservation:
    return DiscoveryObservation(
        repo_full_name=value["repo_full_name"],
        library_id=value["library_id"],
        signal_id=value["signal_id"],
        source=value["source"],
        query_fingerprint=value["query_fingerprint"],
        observed_at=_required_timestamp(
            value.get("observed_at"), field="observation timestamp"
        ),
        visibility=value["visibility"],
        repo_node_id=value.get("repo_node_id"),
        matched_path=value.get("matched_path"),
        matched_blob=value.get("matched_blob"),
        matched_commit=value.get("matched_commit"),
        source_fetched_at=(
            _required_timestamp(
                value.get("source_fetched_at"),
                field="source fetch timestamp",
            )
            if value.get("source_fetched_at") is not None
            else None
        ),
        source_lag_seconds=value.get("source_lag_seconds"),
        partition=value.get("partition"),
    )


def _coverage_gap_from_dict(value: Mapping[str, Any]) -> CoverageGap:
    return CoverageGap(
        code=value["code"],
        detail=value["detail"],
        partition=value.get("partition"),
        retryable=bool(value.get("retryable", False)),
    )


def _coverage_partition_from_dict(
    value: Mapping[str, Any],
) -> CoveragePartition:
    gaps = value.get("gaps") or ()
    return CoveragePartition(
        key=value["key"],
        query=value["query"],
        total_count=value.get("total_count"),
        fetched_count=value["fetched_count"],
        page_count=value["page_count"],
        complete=value["complete"],
        capped=bool(value.get("capped", False)),
        subdivided=bool(value.get("subdivided", False)),
        incomplete_results=bool(value.get("incomplete_results", False)),
        extension=value.get("extension"),
        size_min=value.get("size_min"),
        size_max=value.get("size_max"),
        gaps=tuple(_coverage_gap_from_dict(gap) for gap in gaps),
    )


def _discovery_result_from_task_result(
    value: Mapping[str, Any],
) -> DiscoveryResult:
    try:
        if (
            value.get("version") != 1
            or value.get("kind") != "discovery-query"
        ):
            raise ValueError("unsupported discovery journal version")
        raw_certificate = value["certificate"]
        certificate = CoverageCertificate(
            source=raw_certificate["source"],
            library_id=raw_certificate["library_id"],
            query_fingerprint=raw_certificate["query_fingerprint"],
            epoch_started_at=_required_timestamp(
                raw_certificate.get("epoch_started_at"),
                field="coverage start timestamp",
            ),
            epoch_completed_at=(
                _required_timestamp(
                    raw_certificate.get("epoch_completed_at"),
                    field="coverage completion timestamp",
                )
                if raw_certificate.get("epoch_completed_at") is not None
                else None
            ),
            complete=raw_certificate["complete"],
            terminal=raw_certificate["terminal"],
            observations_count=raw_certificate["observations_count"],
            quarantined_count=raw_certificate.get(
                "quarantined_count", 0
            ),
            partitions=tuple(
                _coverage_partition_from_dict(partition)
                for partition in raw_certificate.get("partitions") or ()
            ),
            intentional_skips=tuple(
                raw_certificate.get("intentional_skips") or ()
            ),
            gaps=tuple(
                _coverage_gap_from_dict(gap)
                for gap in raw_certificate.get("gaps") or ()
            ),
            source_lag_max_seconds=raw_certificate.get(
                "source_lag_max_seconds"
            ),
            metrics=dict(raw_certificate.get("metrics") or {}),
        )
        return DiscoveryResult(
            observations=tuple(
                _discovery_observation_from_dict(observation)
                for observation in value.get("observations") or ()
            ),
            quarantined_observations=tuple(
                _discovery_observation_from_dict(observation)
                for observation in value.get(
                    "quarantined_observations"
                ) or ()
            ),
            certificate=certificate,
        )
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        if isinstance(exc, PipelineError):
            raise
        raise PipelineError(
            "journaled discovery result is malformed"
        ) from exc


def _metadata_result_to_task_result(
    result: GraphQLResolution,
) -> dict[str, Any]:
    repositories = []
    for repository in result.repositories:
        item = {
            "request_key": repository.request_key,
            "requested_node_id": repository.requested_node_id,
            "requested_full_name": repository.requested_full_name,
            "admitted_public": repository.explicitly_public,
            "status": repository.status,
            "error_count": len(repository.errors),
        }
        if repository.explicitly_public:
            item.update(
                {
                    "node_id": repository.node_id,
                    "full_name": repository.full_name,
                    "is_fork": repository.is_fork,
                    "is_archived": repository.is_archived,
                    "default_branch": repository.default_branch,
                    "head_oid": repository.head_oid,
                    "renamed": repository.renamed,
                    "disk_usage_kb": repository.disk_usage_kb,
                    "description": repository.description,
                    "stars": repository.stars,
                    "forks": repository.forks,
                    "language": repository.language,
                    "created_at": repository.created_at,
                    "pushed_at": repository.pushed_at,
                }
            )
        repositories.append(item)
    return {
        "version": 2,
        "kind": "github-metadata-batch",
        "repositories": repositories,
        "error_count": len(result.errors),
        "request_count": result.request_count,
        "points_used": result.points_used,
        "remaining": result.remaining,
        "reset_at": result.reset_at,
    }


def _metadata_result_from_task_result(
    value: Mapping[str, Any],
) -> GraphQLResolution:
    try:
        if (
            value.get("version") != 2
            or value.get("kind") != "github-metadata-batch"
        ):
            raise ValueError("unsupported metadata journal version")
        repositories = []
        for raw in value.get("repositories") or ():
            item = dict(raw)
            explicitly_public = item.pop("admitted_public") is True
            requested_node_id = item.get("requested_node_id")
            requested_full_name = item.get("requested_full_name")
            repositories.append(
                RepositoryMetadata(
                    request_key=item["request_key"],
                    requested_node_id=requested_node_id,
                    requested_full_name=requested_full_name,
                    node_id=(
                        item.get("node_id")
                        if explicitly_public
                        else requested_node_id
                    ),
                    full_name=(
                        item.get("full_name")
                        if explicitly_public
                        else requested_full_name
                    ),
                    visibility="PUBLIC" if explicitly_public else None,
                    is_private=False if explicitly_public else None,
                    is_fork=(
                        item.get("is_fork")
                        if explicitly_public
                        else None
                    ),
                    is_archived=(
                        item.get("is_archived")
                        if explicitly_public
                        else None
                    ),
                    default_branch=(
                        item.get("default_branch")
                        if explicitly_public
                        else None
                    ),
                    head_oid=(
                        item.get("head_oid")
                        if explicitly_public
                        else None
                    ),
                    renamed=(
                        bool(item.get("renamed"))
                        if explicitly_public
                        else False
                    ),
                    status=item["status"],
                    errors=tuple(
                        "github metadata error"
                        for _index in range(
                            int(item.get("error_count") or 0)
                        )
                    ),
                    disk_usage_kb=(
                        item.get("disk_usage_kb")
                        if explicitly_public
                        else None
                    ),
                    description=(
                        item.get("description")
                        if explicitly_public
                        else None
                    ),
                    stars=(
                        int(item.get("stars") or 0)
                        if explicitly_public
                        else 0
                    ),
                    forks=(
                        int(item.get("forks") or 0)
                        if explicitly_public
                        else 0
                    ),
                    language=(
                        item.get("language")
                        if explicitly_public
                        else None
                    ),
                    created_at=(
                        item.get("created_at")
                        if explicitly_public
                        else None
                    ),
                    pushed_at=(
                        item.get("pushed_at")
                        if explicitly_public
                        else None
                    ),
                )
            )
        errors = tuple(
            GraphQLError(
                message="github metadata error",
                request_key=None,
                error_type=None,
            )
            for _index in range(int(value.get("error_count") or 0))
        )
        return GraphQLResolution(
            repositories=tuple(repositories),
            errors=errors,
            request_count=int(value["request_count"]),
            points_used=int(value["points_used"]),
            remaining=int(value["remaining"]),
            reset_at=value.get("reset_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PipelineError(
            "journaled GitHub metadata result is malformed"
        ) from exc


def _metadata_lookup_universe_sha256(lookups) -> str:
    payload = sorted(
        (
            {
                "node_id": lookup.node_id,
                "full_name": lookup.full_name,
            }
            for lookup in lookups
        ),
        key=lambda item: (
            item["node_id"] or "",
            (item["full_name"] or "").casefold(),
        ),
    )
    return hashlib.sha256(
        fingerprint_json(payload).encode("utf-8")
    ).hexdigest()


def _metadata_input_context_sha256(
    observations,
    legacy,
    state_known,
) -> str:
    """Fingerprint the exact lookup-driving context for a metadata epoch."""
    payload = {
        "discovery_identities": sorted(
            {
                (
                    observation.repo_node_id or "",
                    observation.repo_full_name.casefold(),
                )
                for observation in observations
            }
        ),
        "legacy_names": sorted(
            str(name).casefold() for name in legacy
        ),
        "state_identities": sorted(
            (
                str(node_id or ""),
                str(full_name).casefold(),
            )
            for node_id, full_name in state_known
        ),
    }
    return hashlib.sha256(
        fingerprint_json(payload).encode("utf-8")
    ).hexdigest()


def _canonical_repository_identity(item) -> tuple[str | None, str | None]:
    """Return GitHub's current canonical repository identity.

    Discovery node-ID strings are not authoritative because GitHub has used
    more than one serialization for the same repository.  A metadata result's
    canonical node ID and canonical full name must agree everywhere an alias is
    bound.
    """
    node_id = getattr(item, "node_id", None)
    full_name = getattr(item, "full_name", None)
    return (
        node_id if isinstance(node_id, str) and node_id else None,
        (
            full_name.casefold()
            if isinstance(full_name, str) and full_name
            else None
        ),
    )


def _canonical_metadata_identity_indexes(items):
    """Build collision-checked canonical, requested, and public indexes."""
    resolved_by_name = {}
    resolved_by_node = {}
    publishable_by_name = {}

    def bind(index, key, item, *, kind):
        if not isinstance(key, str) or not key:
            return
        existing = index.get(key)
        if (
            existing is not None
            and _canonical_repository_identity(existing)
            != _canonical_repository_identity(item)
        ):
            raise PipelineError(
                "GitHub metadata %s collision for %s" % (kind, key)
            )
        index[key] = item

    for item in items:
        node_id, full_name = _canonical_repository_identity(item)
        if node_id is None and full_name is None:
            continue
        if node_id is not None:
            bind(resolved_by_node, node_id, item, kind="canonical-node")
            bind(
                resolved_by_node,
                getattr(item, "requested_node_id", None),
                item,
                kind="requested-node",
            )
        if full_name is not None:
            bind(resolved_by_name, full_name, item, kind="canonical-name")
        requested_name = getattr(item, "requested_full_name", None)
        bind(
            resolved_by_name,
            (
                requested_name.casefold()
                if isinstance(requested_name, str)
                and requested_name
                else None
            ),
            item,
            kind="requested-name",
        )
        if (
            node_id is not None
            and full_name is not None
            and getattr(item, "publishable", False)
            and getattr(item, "head_oid", None)
            and not _repository_excluded(
                getattr(item, "full_name", "")
            )
        ):
            bind(
                publishable_by_name,
                full_name,
                item,
                kind="publishable-name",
            )
    return resolved_by_name, resolved_by_node, publishable_by_name


def _resolve_canonical_observation_identity(
    observation,
    *,
    resolved_by_name,
    resolved_by_node,
):
    """Resolve one discovery observation without trusting its ID encoding."""
    node_item = (
        resolved_by_node.get(observation.repo_node_id)
        if observation.repo_node_id
        else None
    )
    name_item = resolved_by_name.get(
        observation.repo_full_name.casefold()
    )
    if (
        node_item is not None
        and name_item is not None
        and _canonical_repository_identity(node_item)
        != _canonical_repository_identity(name_item)
    ):
        raise PipelineError(
            "discovery node/name identity collision for %s"
            % observation.repo_full_name
        )
    if node_item is not None:
        if name_item is None:
            aliases = {
                value.casefold()
                for value in (
                    getattr(node_item, "full_name", None),
                    getattr(node_item, "requested_full_name", None),
                )
                if isinstance(value, str) and value
            }
            if observation.repo_full_name.casefold() not in aliases:
                raise PipelineError(
                    "discovery node/name identity mismatch for %s"
                    % observation.repo_full_name
                )
        return node_item, "exact_node"
    if name_item is not None:
        return (
            name_item,
            (
                "name_fallback_after_node_miss"
                if observation.repo_node_id
                else "name_only"
            ),
        )
    return None, "unresolved"


def _final_visibility_set(
    current: Mapping[str, Any],
) -> tuple[tuple[str, ...], str]:
    """Return the exact stable-ID set named by the would-be publication."""
    node_ids = []
    for repository in current.get("repos") or ():
        if not isinstance(repository, Mapping):
            raise PipelineError(
                "would-be publication contains a malformed repository"
            )
        node_id = repository.get("repository_node_id")
        if not isinstance(node_id, str) or not node_id:
            raise PipelineError(
                "would-be publication repository lacks a stable node ID"
            )
        node_ids.append(node_id)
    if len(node_ids) != len(set(node_ids)):
        raise PipelineError(
            "would-be publication contains duplicate stable node IDs"
        )
    ordered = tuple(sorted(node_ids))
    return ordered, fingerprint("final-visibility-set-v1", ordered)


def _assert_final_visibility_part(
    result: GraphQLResolution,
    expected_node_ids: Iterable[str],
    *,
    certified_missing_node_ids: Iterable[str] = (),
) -> None:
    """Require an exact, explicitly public/non-fork/non-archived response."""
    expected = tuple(expected_node_ids)
    expected_keys = {"node:" + node_id for node_id in expected}
    actual_keys = {
        repository.request_key for repository in result.repositories
    }
    if actual_keys != expected_keys or len(result.repositories) != len(expected):
        raise PipelineError(
            "final GitHub visibility batch did not exactly cover its stable IDs"
        )
    if not result.complete or result.errors:
        raise PipelineError(
            "final GitHub visibility batch contains partial errors"
        )
    certified_missing = set(certified_missing_node_ids)
    for repository in result.repositories:
        if repository.requested_node_id in certified_missing:
            if (
                repository.requested_node_id not in expected
                or repository.requested_full_name is not None
                or repository.node_id not in {
                    None, repository.requested_node_id
                }
                or repository.full_name is not None
                or repository.status != "missing"
                or repository.errors
            ):
                raise PipelineError(
                    "certified final GitHub visibility rejection changed"
                )
            continue
        if (
            repository.requested_node_id not in expected
            or repository.requested_full_name is not None
            or repository.node_id != repository.requested_node_id
            or repository.status != "ok"
            or repository.visibility != "PUBLIC"
            or repository.is_private is not False
            or repository.is_fork is not False
            or repository.is_archived is not False
        ):
            raise PipelineError(
                "final GitHub visibility check found a private, gone, "
                "forked, archived, or unverified repository"
            )


def _graphql_journal_budget(
    state: StateDB,
    run_id: str,
) -> dict[str, Any]:
    """Account every completed same-run GraphQL task across fresh epochs."""
    run = state.connection.execute(
        "SELECT plan_json FROM runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if run is None:
        raise PipelineError("GraphQL usage run is unknown")
    try:
        execution = (
            json.loads(run["plan_json"] or "{}").get(
                "execution_contract"
            )
            or {}
        )
        historical = dict(
            execution.get("historical_graphql_usage") or {}
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "historical GraphQL usage contract is malformed"
        ) from exc
    historical_requests = int(
        historical.get("request_count", 0) or 0
    )
    historical_points = int(
        historical.get("points_used", 0) or 0
    )
    historical_remaining = historical.get("remaining")
    historical_reset = historical.get("reset_at")
    if (
        historical_requests < 0
        or historical_points < 0
        or (
            historical_remaining is not None
            and (
                not isinstance(historical_remaining, int)
                or isinstance(historical_remaining, bool)
                or historical_remaining < 0
            )
        )
        or (
            historical_reset is not None
            and not isinstance(historical_reset, str)
        )
    ):
        raise PipelineError(
            "historical GraphQL usage contract is invalid"
        )
    graphql_resume = execution.get("graphql_resume_control")
    if graphql_resume is not None:
        try:
            base_rows = list(state.connection.execute(
                """
                SELECT task_key,result_json FROM tasks
                WHERE run_id=? AND stage='github-metadata-batch'
                  AND status='complete' AND task_key NOT LIKE 'fresh:%'
                ORDER BY task_id
                """,
                (run_id,),
            ))
            result_universe = [{
                "task_key": str(row["task_key"]),
                "result_sha256": hashlib.sha256(
                    str(row["result_json"]).encode("utf-8")
                ).hexdigest(),
            } for row in base_rows]
            embedded_result_sha256 = hashlib.sha256(
                fingerprint_json(result_universe).encode("utf-8")
            ).hexdigest()
            embedded_requests = 0
            embedded_points = 0
            for row in base_rows:
                document = json.loads(row["result_json"])
                if (
                    not isinstance(document, Mapping)
                    or document.get("version") != 2
                    or document.get("kind") != "github-metadata-batch"
                ):
                    raise ValueError("invalid embedded metadata result")
                embedded_requests += int(
                    document.get("request_count") or 0
                )
                embedded_points += int(document.get("points_used") or 0)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "embedded preseeded GraphQL usage is malformed"
            ) from exc
        if (
            len(base_rows) != graphql_resume["embedded_task_count"]
            or embedded_requests
            != graphql_resume["embedded_request_count"]
            or embedded_points != graphql_resume["embedded_points_used"]
            or embedded_result_sha256
            != graphql_resume["embedded_result_universe_sha256"]
            or historical_requests != embedded_requests
            or historical_points != embedded_points
        ):
            raise PipelineError(
                "embedded preseeded GraphQL usage proof changed"
            )
        # The successor's immutable preseeded task documents are the durable
        # representation of these historical calls.  The reviewed control
        # proves that adding both representations double-charged one epoch.
        historical_requests = 0
        historical_points = 0
        historical_remaining = None
        historical_reset = None
    documents = []
    for row in state.connection.execute(
        """
        SELECT result_json FROM tasks
        WHERE run_id=? AND status='complete'
          AND stage IN (
              'github-metadata-batch',
              'github-final-visibility-batch'
          )
        ORDER BY task_id
        """,
        (run_id,),
    ):
        try:
            document = json.loads(row["result_json"])
        except (TypeError, ValueError):
            continue
        if (
            isinstance(document, Mapping)
            and document.get("version") == 2
            and document.get("kind") == "github-metadata-batch"
        ):
            documents.append(document)
    now = datetime.datetime.now(datetime.timezone.utc)
    active_documents = []
    historical_active = False
    if historical_remaining is not None:
        if historical_reset is None:
            historical_active = True
        else:
            try:
                reset = datetime.datetime.fromisoformat(
                    historical_reset.replace("Z", "+00:00")
                )
            except ValueError:
                historical_active = True
            else:
                historical_active = (
                    reset.tzinfo is None or reset > now
                )
    for document in documents:
        raw_reset = document.get("reset_at")
        if raw_reset is None:
            active_documents.append(document)
            continue
        try:
            reset = datetime.datetime.fromisoformat(
                str(raw_reset).replace("Z", "+00:00")
            )
        except ValueError:
            # Malformed window data is treated conservatively as still active.
            active_documents.append(document)
            continue
        if reset.tzinfo is None or reset > now:
            active_documents.append(document)
    retry_reserve = execution.get("visibility_transport_retry_control")
    reserved_requests = 0
    reserved_points = 0
    if retry_reserve is not None:
        try:
            reserved_points = int(
                retry_reserve["reserved_unobserved_points"]
            )
            reserved_requests = int(retry_reserve["failed_attempt_count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PipelineError(
                "GraphQL transport retry reserve is malformed"
            ) from exc
        if reserved_points != 1 or reserved_requests != 1:
            raise PipelineError(
                "GraphQL transport retry reserve is invalid"
            )
    recovery_reserve = execution.get("visibility_epoch_recovery_control")
    if recovery_reserve is not None:
        try:
            additional_points = int(
                recovery_reserve["additional_reserved_unobserved_points"]
            )
            additional_requests = int(
                recovery_reserve["additional_failed_attempt_count"]
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PipelineError(
                "GraphQL epoch recovery reserve is malformed"
            ) from exc
        if additional_points != 1 or additional_requests != 1:
            raise PipelineError("GraphQL epoch recovery reserve is invalid")
        reserved_points += additional_points
        reserved_requests += additional_requests
    return {
        "request_count": historical_requests + sum(
            int(document.get("request_count") or 0)
            for document in documents
        ) + reserved_requests,
        "points_used": historical_points + sum(
            int(document.get("points_used") or 0)
            for document in documents
        ) + reserved_points,
        "remaining": (
            min(
                [
                    int(document["remaining"])
                    for document in active_documents
                ]
                + (
                    [int(historical_remaining)]
                    if historical_active
                    else []
                )
            )
            if active_documents or historical_active
            else None
        ),
        "reset_at": next(
            (
                document.get("reset_at")
                for document in reversed(active_documents)
                if document.get("reset_at") is not None
            ),
            historical_reset if historical_active else None,
        ),
    }


def _final_visibility_age_seconds(
    attestation: Mapping[str, Any],
    *,
    now: datetime.datetime | None = None,
) -> float:
    checked_at = attestation.get("checked_at")
    if not isinstance(checked_at, str):
        raise PipelineError("final visibility attestation has no checked_at")
    try:
        checked = datetime.datetime.fromisoformat(
            checked_at.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise PipelineError(
            "final visibility attestation checked_at is malformed"
        ) from exc
    if checked.tzinfo is None:
        raise PipelineError(
            "final visibility attestation checked_at has no timezone"
        )
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0.0, (now - checked).total_seconds())


def _assert_final_visibility_fresh(
    attestation: Mapping[str, Any],
) -> float:
    age = _final_visibility_age_seconds(attestation)
    if age > FINAL_VISIBILITY_MAX_AGE_SECONDS:
        raise PipelineError(
            "final GitHub visibility attestation is too old to install "
            "(%.1fs > %ds)"
            % (age, FINAL_VISIBILITY_MAX_AGE_SECONDS)
        )
    return age


def _task_row(state: StateDB, task_id: int) -> dict[str, Any]:
    row = state.connection.execute(
        "SELECT * FROM tasks WHERE task_id=?", (int(task_id),)
    ).fetchone()
    if row is None:
        raise PipelineError("journaled network task disappeared")
    return dict(row)


def _completed_task_document(
    state: StateDB,
    task_id: int,
) -> Mapping[str, Any] | None:
    row = _task_row(state, task_id)
    if row["status"] != "complete":
        if row["status"] == "failed":
            raise PipelineError(
                "journaled network task exhausted its retry budget"
            )
        return None
    try:
        value = json.loads(row["result_json"])
    except (TypeError, ValueError) as exc:
        raise PipelineError(
            "journaled network task result is unreadable"
        ) from exc
    if not isinstance(value, Mapping):
        raise PipelineError(
            "journaled network task result is malformed"
        )
    return value


def _prior_diff(current: dict, data_dir: Path) -> dict:
    prior_v2 = _load_json(data_dir / "v2" / "manifest.json", {})
    if (
        isinstance(prior_v2.get("release"), Mapping)
        and isinstance(prior_v2["release"].get("id"), str)
    ):
        prior = {
            "generated_at": (
                prior_v2.get("generated_at")
                or prior_v2["release"].get("generated_at")
            ),
            "libraries": prior_v2.get("libraries") or [],
        }
    else:
        # One-time cutover fallback only. After V2 exists, deltas always chain
        # from the immediately preceding V2 release.
        prior = _load_json(data_dir / "current.json", {})
    prior_date = (prior.get("generated_at") or "")[:10] or None
    prior_counts = {
        item["id"]: item.get("confirmed_count", 0)
        for item in prior.get("libraries", ())
        if isinstance(item, dict) and item.get("id")
    }
    per_library = []
    for library in current["libraries"]:
        confirmed_count = library.get("confirmed_count")
        library["delta_since_last"] = (
            confirmed_count - prior_counts.get(library["id"], 0)
            if isinstance(confirmed_count, int)
            else None
        )
        per_library.append({
            "id": library["id"],
            "name": library["name"],
            "delta": library["delta_since_last"],
        })
    new_names = []
    for repo in current["repos"]:
        repo_new = False
        for entry in repo["libraries"]:
            adopted = entry.get("first_integration")
            entry["is_new"] = bool(prior_date and adopted and adopted > prior_date)
            repo_new = repo_new or entry["is_new"]
        repo["is_new"] = repo_new
        if repo_new:
            new_names.append(repo["full_name"])
    current["is_bootstrap"] = not bool(prior_date)
    current["prev_refresh"] = prior_date
    return {
        "generated_at": current["generated_at"],
        "prev_refresh": prior_date,
        "is_bootstrap": current["is_bootstrap"],
        "per_library": per_library,
        "new_repos": sorted(new_names),
        "scan_error_count": 0,
    }


def _discovery_stats(
    libraries: Iterable[Mapping[str, Any]], discovery_metrics: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    certificates_by_library: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in discovery_metrics.get("certificates", ()):
        if not isinstance(raw, Mapping):
            continue
        # Incomplete advisory observations remain durable discovery/stage
        # diagnostics, but they are not publication certificates.  The public
        # quality document may contain only terminal complete certificates;
        # otherwise an advisory timeout is accidentally presented as coverage
        # authority beside the required complete GitHub epoch.
        if raw.get("complete") is not True or raw.get("terminal") is not True:
            continue
        library_id = raw.get("library_id")
        if isinstance(library_id, str):
            certificates_by_library[library_id].append(dict(raw))

    result: dict[str, dict[str, Any]] = {}
    for library in libraries:
        library_id = library["id"]
        certificates = sorted(
            certificates_by_library.get(library_id, ()),
            key=lambda item: (
                str(item.get("source") or ""),
                str(item.get("query_fingerprint") or ""),
            ),
        )
        if not certificates:
            result[library_id] = {
                "evidence_kind": "not-evaluated",
                "coverage_gaps": [],
                "sources": {},
                "source_lag_max_seconds": None,
                "stale": True,
                "carried_forward": False,
            }
            continue
        gaps = []
        sources: dict[str, dict[str, Any]] = {}
        lag_values = []
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for certificate in certificates:
            source = str(certificate.get("source") or "")
            by_source[source].append(certificate)
            lag = certificate.get("source_lag_max_seconds")
            if isinstance(lag, int) and not isinstance(lag, bool):
                lag_values.append(lag)
            for gap in certificate.get("gaps") or ():
                if isinstance(gap, Mapping):
                    gaps.append({
                        "source": source,
                        "query_fingerprint": certificate.get(
                            "query_fingerprint"
                        ),
                        **dict(gap),
                    })
        for source, source_certificates in sorted(by_source.items()):
            source_lags = [
                item["source_lag_max_seconds"]
                for item in source_certificates
                if isinstance(item.get("source_lag_max_seconds"), int)
                and not isinstance(item.get("source_lag_max_seconds"), bool)
            ]
            sources[source] = {
                "certificate_count": len(source_certificates),
                "complete": all(
                    item.get("complete") is True
                    for item in source_certificates
                ),
                "terminal": all(
                    item.get("terminal") is True
                    for item in source_certificates
                ),
                "observations_count": sum(
                    int(item.get("observations_count") or 0)
                    for item in source_certificates
                ),
                "quarantined_count": sum(
                    int(item.get("quarantined_count") or 0)
                    for item in source_certificates
                ),
                "source_lag_max_seconds": (
                    max(source_lags) if source_lags else None
                ),
                "epoch_started_at": min(
                    str(item.get("epoch_started_at") or "")
                    for item in source_certificates
                ),
                "epoch_completed_at": max(
                    str(item.get("epoch_completed_at") or "")
                    for item in source_certificates
                ),
                "carried_forward": any(
                    item.get("carried_forward") is True
                    for item in source_certificates
                ),
                "as_of": max(
                    str(
                        item.get("as_of")
                        or item.get("epoch_completed_at")
                        or ""
                    )
                    for item in source_certificates
                ),
                "stale": any(
                    item.get("stale") is True
                    for item in source_certificates
                ),
            }
        result[library_id] = {
            "evidence_kind": "certificates",
            "coverage_gaps": sorted(
                gaps,
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":")
                ),
            ),
            "sources": sources,
            "source_lag_max_seconds": max(lag_values) if lag_values else None,
            "certificates": certificates,
            "stale": any(
                item.get("stale") is True for item in certificates
            ),
            "carried_forward": any(
                item.get("carried_forward") is True
                for item in certificates
            ),
        }
    return result


def _materialize_family_rollup_entries(
    repositories: list[dict[str, Any]],
    *,
    selected_library_ids: set[str] | None = None,
) -> None:
    """Add one effective confirmed parent-family row per repository.

    Component confirmation is stronger than a weak parent-family mention.  A
    repository still has exactly one row per library, so an existing bundled
    or targeted parent row must be promoted to confirmed while retaining its
    original classification as audit provenance.  Otherwise the unique-family
    card counts the repository as confirmed while publication emits it as a
    weaker row.
    """
    from .portfolio import derive_family_rollups

    family_rollups = derive_family_rollups(repositories)
    repo_by_name = {repo["full_name"]: repo for repo in repositories}
    for parent_id, rollup_rows in family_rollups.items():
        if (
            selected_library_ids is not None
            and parent_id not in selected_library_ids
        ):
            continue
        for rollup in rollup_rows:
            repo = repo_by_name[rollup["full_name"]]
            existing = next(
                (
                    entry for entry in repo["libraries"]
                    if entry["library_id"] == parent_id
                ),
                None,
            )
            if existing is None:
                repo["libraries"].append({
                    "library_id": parent_id,
                    "classification": "confirmed",
                    "language": None,
                    "first_integration": rollup.get("first_integration"),
                    "first_integration_commit": rollup.get(
                        "first_integration_commit"
                    ) or "",
                    "own_source_files": [],
                    "own_source_file_count": 0,
                    "vendored_present": False,
                    "ai_on_integration_commit": False,
                    "ai_on_integration_agents": [],
                    "operators": list(rollup.get("component_ids") or ()),
                    "derived_family_rollup": True,
                    "component_ids": list(rollup.get("component_ids") or ()),
                })
            else:
                prior_classification = existing.get("classification")
                if prior_classification != "confirmed":
                    existing["direct_parent_classification"] = (
                        prior_classification
                    )
                    existing["direct_parent_first_integration"] = (
                        existing.get("first_integration")
                    )
                    existing["direct_parent_first_integration_commit"] = (
                        existing.get("first_integration_commit") or ""
                    )
                    existing["classification"] = "confirmed"
                    existing["derived_family_rollup"] = True
                current_date = existing.get("first_integration")
                family_date = rollup.get("first_integration")
                if family_date and (
                    not current_date or family_date < current_date
                ):
                    existing["first_integration"] = family_date
                    existing["first_integration_commit"] = (
                        rollup.get("first_integration_commit") or ""
                    )
                existing["component_ids"] = list(
                    rollup.get("component_ids") or ()
                )
                existing["family_rollup"] = True
            confirmed_dates = [
                entry.get("first_integration")
                for entry in repo["libraries"]
                if entry.get("classification") == "confirmed"
                and entry.get("first_integration")
            ]
            repo["earliest_integration"] = (
                min(confirmed_dates) if confirmed_dates else None
            )


def _restore_direct_parent_entries(
    repositories: list[dict[str, Any]],
) -> None:
    """Remove legacy component-to-parent materialization in place.

    Non-NVPL components are independent tracked libraries.  Older Phase 8
    materialization added or promoted parent rows so a component could inflate
    its parent card.  Fresh scans no longer do that, but carried or resumed
    evidence may still contain the explicit provenance flags.  Restore only
    the direct parent evidence and leave every component row untouched.
    """
    for repo in repositories:
        restored = []
        for entry in repo.get("libraries", ()):
            if not isinstance(entry, dict):
                restored.append(entry)
                continue
            derived = entry.get("derived_family_rollup") is True
            direct_classification = entry.get(
                "direct_parent_classification"
            )
            if derived and not isinstance(direct_classification, str):
                # This row existed only because a component was confirmed.
                continue
            if derived:
                entry["classification"] = direct_classification
                if "direct_parent_first_integration" in entry:
                    entry["first_integration"] = entry.get(
                        "direct_parent_first_integration"
                    )
                    entry["first_integration_commit"] = entry.get(
                        "direct_parent_first_integration_commit"
                    ) or ""
            for key in (
                "component_ids",
                "derived_family_rollup",
                "direct_parent_classification",
                "direct_parent_first_integration",
                "direct_parent_first_integration_commit",
                "family_rollup",
            ):
                entry.pop(key, None)
            restored.append(entry)
        repo["libraries"] = restored
        confirmed_dates = [
            entry.get("first_integration")
            for entry in restored
            if isinstance(entry, Mapping)
            and entry.get("classification") == "confirmed"
            and entry.get("first_integration")
        ]
        repo["earliest_integration"] = (
            min(confirmed_dates) if confirmed_dates else None
        )


def _retirement_eligible_library_ids(
    libraries: Iterable[Mapping[str, Any]],
    discovery_metrics: Mapping[str, Any],
) -> set[str]:
    """Require fresh terminal coverage from both discovery sources."""
    by_library: dict[str, dict[str, dict[str, Mapping[str, Any]]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    for certificate in discovery_metrics.get("certificates", ()):
        if not isinstance(certificate, Mapping):
            continue
        library_id = certificate.get("library_id")
        source = certificate.get("source")
        query_fp = certificate.get("query_fingerprint")
        if all(isinstance(value, str) and value for value in (
            library_id, source, query_fp
        )):
            by_library[library_id][source][query_fp] = certificate
    eligible = set()
    for library in libraries:
        library_id = library["id"]
        expected = {
            "github-code-search": {
                github_query_fingerprint(pack)
                for pack in query_packs(library)
            },
        }
        sources = by_library.get(library_id, {})
        source = "github-code-search"
        if not (
            expected[source].issubset(sources.get(source, {}))
            and all(
                sources[source][query_fp].get("complete") is True
                and sources[source][query_fp].get("terminal") is True
                and sources[source][query_fp].get("stale") is not True
                for query_fp in expected[source]
            )
        ):
            continue
        eligible.add(library_id)
    return eligible


def _carry_forward_unselected_v1(
    repositories: list[dict[str, Any]],
    data_dir: Path,
    selected_library_ids: set[str],
    public_name_map: Mapping[str, str],
    public_metadata_map: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    include_previously_measured: bool = False,
) -> tuple[list[dict[str, Any]], set[str], dict[str, Any]]:
    """Merge unselected V1 evidence only after current public admission.

    A V1 row is evidence, never authority for current visibility or identity.
    Every carried row therefore has to map to a repository that the current
    metadata pass admitted explicitly as public/non-fork/non-archived.
    """
    legacy = _load_json(data_dir / "current.json", {})
    legacy_repositories = legacy.get("repos") or []
    by_name = {repo["full_name"]: repo for repo in repositories}
    prior_v2 = _load_json(data_dir / "v2" / "manifest.json", {})
    previously_measured_ids = {
        card["id"]
        for card in prior_v2.get("libraries", ())
        if isinstance(card, Mapping)
        and isinstance(card.get("id"), str)
        and card.get("collection_status") == "collected"
    }
    state_backed_ids = {
        entry["library_id"]
        for repository in repositories
        for entry in repository.get("libraries", ())
        if isinstance(entry, Mapping)
        and isinstance(entry.get("library_id"), str)
    }
    carried_library_ids = {
        card["id"]
        for card in legacy.get("libraries", ())
        if isinstance(card, Mapping)
        and isinstance(card.get("id"), str)
        and card["id"] not in selected_library_ids
        and (
            include_previously_measured
            or card["id"] not in previously_measured_ids
        )
        and card["id"] not in state_backed_ids
    }
    libraries_by_id = {
        library["id"]: library for library in config.LIBRARIES
    }
    for legacy_repo in legacy_repositories:
        if not isinstance(legacy_repo, Mapping):
            continue
        legacy_name = legacy_repo.get("full_name")
        if not isinstance(legacy_name, str):
            continue
        name = public_name_map.get(legacy_name.casefold())
        if not name or _repository_excluded(name):
            continue
        current_metadata = _preserve_repository_lineage(
            (public_metadata_map or {}).get(name.casefold()) or {},
            legacy_repo,
        )
        retained = [
            copy.deepcopy(entry)
            for entry in legacy_repo.get("libraries", ())
            if isinstance(entry, Mapping)
            and entry.get("library_id") in carried_library_ids
            and entry.get("library_id") not in selected_library_ids
            and entry.get("library_id") in libraries_by_id
            and not _library_repository_excluded(
                name,
                libraries_by_id[entry["library_id"]],
                current_metadata,
            )
        ]
        if not retained:
            continue
        if include_previously_measured:
            legacy_as_of = legacy.get("generated_at")
            if (
                not isinstance(legacy_as_of, str)
                or not legacy_as_of.strip()
            ):
                raise PipelineError(
                    "carried-forward V1 evidence lacks as-of provenance"
                )
            for entry in retained:
                entry["carried_forward"] = True
                entry["stale"] = True
                entry["as_of"] = legacy_as_of
        current = by_name.get(name)
        if current is None:
            current = copy.deepcopy(dict(legacy_repo))
            current["full_name"] = name
            current["html_url"] = "https://github.com/" + name
            current["libraries"] = []
            current["visibility"] = "PUBLIC"
            current["repository_node_id"] = current_metadata.get("node_id")
            repositories.append(current)
            by_name[name] = current
        else:
            # Preserve V1 display metadata for carried rows when fresh metadata
            # is absent, while keeping state-backed operational fields.
            for key, value in legacy_repo.items():
                if key == "libraries":
                    continue
                if key not in current or current[key] in (None, "", [], {}):
                    current[key] = copy.deepcopy(value)
        present = {
            entry.get("library_id")
            for entry in current.get("libraries", ())
            if isinstance(entry, Mapping)
        }
        for entry in retained:
            library_id = entry.get("library_id")
            if library_id not in present:
                current.setdefault("libraries", []).append(entry)
                present.add(library_id)
        current["visibility"] = "PUBLIC"
        if current_metadata.get("node_id"):
            current["repository_node_id"] = current_metadata["node_id"]
        confirmed_dates = [
            entry.get("first_integration")
            for entry in current.get("libraries", ())
            if entry.get("classification") == "confirmed"
            and entry.get("first_integration")
        ]
        current["earliest_integration"] = (
            min(confirmed_dates) if confirmed_dates else None
        )
    return repositories, carried_library_ids, legacy


def _preserve_nvpl_component_memberships(
    repositories: list[dict[str, Any]],
    legacy: Mapping[str, Any],
    public_name_map: Mapping[str, str],
) -> None:
    """Preserve exact V1 NVPL subtypes for current-public V2 rows.

    V2 classification remains authoritative for every row. Existing
    current-public V1 repositories retain only their reviewed V1 component
    membership; no V1 band or other row fields are merged.
    """
    current_by_name = {
        repository["full_name"]: repository
        for repository in repositories
        if isinstance(repository.get("full_name"), str)
    }
    for prior_repository in legacy.get("repos", ()):
        if not isinstance(prior_repository, Mapping):
            continue
        prior_name = prior_repository.get("full_name")
        if not isinstance(prior_name, str):
            continue
        current_name = public_name_map.get(prior_name.casefold())
        current_repository = current_by_name.get(current_name)
        if current_repository is None:
            continue
        prior_entry = next((
            entry for entry in prior_repository.get("libraries", ())
            if isinstance(entry, Mapping) and entry.get("library_id") == "nvpl"
        ), None)
        current_entry = next((
            entry for entry in current_repository.get("libraries", ())
            if isinstance(entry, dict) and entry.get("library_id") == "nvpl"
        ), None)
        if prior_entry is not None and current_entry is not None:
            preserve_v1_components(current_entry, prior_entry)


class CollectorPipeline:
    def __init__(
        self,
        *,
        repo_root=".",
        state_path=".state/collector.sqlite3",
        cache_root=".state/git-cache",
        data_dir="data",
        sourcegraph=None,
        github_search=None,
        metadata=None,
        scan_runner=scan_many,
        citation_pipeline=None,
        clock=time.monotonic,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.state_path = (self.repo_root / state_path).resolve()
        self.cache_root = (self.repo_root / cache_root).resolve()
        self.data_dir = (self.repo_root / data_dir).resolve()
        self.sourcegraph = sourcegraph
        self.github_search = github_search
        self.metadata = metadata
        self.scan_runner = scan_runner
        self.citation_pipeline = citation_pipeline
        self.clock = clock
        self._transport_metrics: dict[str, Any] = {}
        self._scan_selection_metrics: dict[str, Any] = {}
        self._scan_attempt_usage: dict[str, Any] = {}
        self._citation_metrics: dict[str, Any] = {}

    def _metadata_batch_size(self) -> int:
        raw = getattr(
            self.metadata, "batch_size", METADATA_BATCH_SIZE
        )
        batch_size = (
            int(raw)
            if isinstance(raw, int) and not isinstance(raw, bool)
            else METADATA_BATCH_SIZE
        )
        if not 1 <= batch_size <= 100:
            raise PipelineError(
                "GitHub metadata adapter has an invalid batch size"
            )
        return batch_size

    def _runtime_report(
        self,
        *,
        mode: str,
        run_class: str | None,
        release_scope: str | None,
        started: float,
        budgets: RunBudgets,
        outcomes,
        cache_before_bytes: int,
        cache_before_keys: frozenset[str],
        discovery_metrics: Mapping[str, Any],
        resolution,
        final_visibility: Mapping[str, Any],
        artifacts: Iterable[Mapping[str, Any]],
        stage_durations: Mapping[str, Mapping[str, Any]],
        task_inventory: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        elapsed = max(0.0, self.clock() - started)
        cache_reader = (
            RepoCache(
                self.cache_root,
                target_bytes=budgets.cache_target_bytes,
                hard_bytes=budgets.cache_hard_bytes,
            )
            if self.cache_root.exists()
            else None
        )
        cache_after = cache_reader.size_bytes() if cache_reader else 0
        cache_after_keys = frozenset(
            str(item["key"]) for item in cache_reader.entries()
        ) if cache_reader else frozenset()
        scans = len(outcomes)
        attempt_usage = dict(self._scan_attempt_usage)
        historical_attempt_usage = (
            attempt_usage.get("historical")
            if isinstance(attempt_usage.get("historical"), Mapping)
            else {}
        )
        current_attempt_usage = (
            attempt_usage.get("current")
            if isinstance(attempt_usage.get("current"), Mapping)
            else attempt_usage
        )
        combined_attempt_usage = (
            attempt_usage.get("combined")
            if isinstance(attempt_usage.get("combined"), Mapping)
            else attempt_usage
        )
        scan_seconds = float(
            attempt_usage.get(
                "seconds",
                sum(float(item.seconds) for item in outcomes),
            )
        )
        git_materialized_bytes = int(
            attempt_usage.get(
                "network_materialized_bytes",
                sum(
                    int(item.network_materialized_bytes)
                    for item in outcomes
                ),
            )
        )
        classifications = _scan_classification_inventory(outcomes)
        transports = {}
        for name, transport in sorted(self._transport_metrics.items()):
            snapshot = getattr(transport, "metrics_snapshot", None)
            if callable(snapshot):
                transports[name] = snapshot()
        rss = _rss_usage_bytes()
        disk = shutil.disk_usage(self.repo_root)
        outliers = sorted(
            (
                {
                    "full_name": item.full_name,
                    "seconds": round(float(item.seconds), 3),
                    "status": item.status,
                    "files_examined": int(item.files_examined),
                    "bytes_examined": int(item.bytes_examined),
                    "cache_bytes": int(item.cache_bytes),
                    "current_tree_triage_seconds": round(
                        float(item.current_tree_triage_seconds), 3
                    ),
                    "history_dating_seconds": round(
                        float(item.history_dating_seconds), 3
                    ),
                    "analysis_seconds": round(
                        float(item.analysis_seconds), 3
                    ),
                    "git_subprocess_count": int(
                        item.git_subprocess_count
                    ),
                    "network_clone_count": int(
                        item.network_clone_count
                    ),
                    "network_fetch_count": int(
                        item.network_fetch_count
                    ),
                    "network_materialized_bytes": int(
                        item.network_materialized_bytes
                    ),
                }
                for item in outcomes
            ),
            key=lambda item: (-item["seconds"], item["full_name"]),
        )[:10]
        artifact_rows = tuple(artifacts)
        artifact_bytes = sum(
            int(item.get("bytes", 0)) for item in artifact_rows
        )
        artifact_largest = sorted(
            (
                {
                    "path": str(item.get("path", "")),
                    "bytes": int(item.get("bytes", 0)),
                }
                for item in artifact_rows
            ),
            key=lambda item: (-item["bytes"], item["path"]),
        )[:10]
        scan_selection = dict(self._scan_selection_metrics)
        discovery_by_library: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "certificates": 0,
                "observations": 0,
                "gaps": 0,
                "queries": 0,
            }
        )
        query_outliers = []
        for raw in discovery_metrics.get("certificates", ()):
            if not isinstance(raw, Mapping):
                continue
            library_id = raw.get("library_id")
            source = raw.get("source")
            if not isinstance(library_id, str) or not isinstance(source, str):
                continue
            row = discovery_by_library[library_id]
            row["certificates"] += 1
            row["queries"] += 1
            row["observations"] += int(raw.get("observations_count") or 0)
            row["gaps"] += len(raw.get("gaps") or ())
            certificate_metrics = raw.get("metrics") or {}
            duration_ms = (
                certificate_metrics.get("durationMs")
                if isinstance(certificate_metrics, Mapping)
                else None
            )
            query_outliers.append(
                {
                    "library_id": library_id,
                    "source": source,
                    "query_fingerprint": str(
                        raw.get("query_fingerprint") or ""
                    ),
                    "duration_ms": (
                        float(duration_ms)
                        if isinstance(duration_ms, (int, float))
                        and not isinstance(duration_ms, bool)
                        else None
                    ),
                    "observations": int(
                        raw.get("observations_count") or 0
                    ),
                    "gaps": len(raw.get("gaps") or ()),
                }
            )
        query_outliers.sort(
            key=lambda item: (
                -(
                    item["duration_ms"]
                    if item["duration_ms"] is not None
                    else -1.0
                ),
                -item["observations"],
                item["library_id"],
                item["source"],
                item["query_fingerprint"],
            )
        )
        slo = _slo_profile(
            mode,
            scans,
            budgets,
            run_class=run_class,
        )
        slo["target_remaining_seconds"] = round(
            slo["target_seconds"] - elapsed, 3
        )
        slo["ceiling_remaining_seconds"] = round(
            slo["ceiling_seconds"] - elapsed, 3
        )
        slo["within_target"] = elapsed <= slo["target_seconds"]
        slo["within_ceiling"] = elapsed <= slo["ceiling_seconds"]
        return {
            "run_class": run_class,
            "release_scope": release_scope,
            "elapsed_seconds": round(elapsed, 3),
            "wall_budget_seconds": budgets.max_wall_seconds,
            "wall_budget_remaining_seconds": round(
                max(0.0, budgets.max_wall_seconds - elapsed), 3
            ),
            "within_wall_budget": elapsed <= budgets.max_wall_seconds,
            "slo": slo,
            "stages": {
                str(stage): dict(values)
                for stage, values in sorted(stage_durations.items())
            },
            "tasks": {
                str(stage): dict(values)
                for stage, values in sorted(task_inventory.items())
            },
            "scan": {
                "selected": scans,
                **scan_selection,
                "workers": budgets.workers,
                "aggregate_worker_seconds": round(scan_seconds, 3),
                "current_tree_triage_seconds": round(float(
                    attempt_usage.get(
                        "current_tree_triage_seconds",
                        sum(
                            float(item.current_tree_triage_seconds)
                            for item in outcomes
                        ),
                    )
                ), 3),
                "history_dating_seconds": round(float(
                    attempt_usage.get(
                        "history_dating_seconds",
                        sum(
                            float(item.history_dating_seconds)
                            for item in outcomes
                        ),
                    )
                ), 3),
                "analysis_seconds": round(float(
                    attempt_usage.get(
                        "analysis_seconds",
                        sum(
                            float(item.analysis_seconds)
                            for item in outcomes
                        ),
                    )
                ), 3),
                "git_subprocess_count": int(
                    attempt_usage.get(
                        "git_subprocess_count",
                        sum(
                            int(item.git_subprocess_count)
                            for item in outcomes
                        ),
                    )
                ),
                "worker_utilization_upper": round(
                    (
                        scan_seconds
                        / max(elapsed * budgets.workers, 0.001)
                    ),
                    4,
                ),
                "cache_hits": sum(bool(item.cache_hit) for item in outcomes),
                "clones": int(
                    attempt_usage.get(
                        "network_clone_count",
                        sum(
                            int(item.network_clone_count)
                            for item in outcomes
                        ),
                    )
                ),
                "fetches": int(
                    attempt_usage.get(
                        "network_fetch_count",
                        sum(
                            int(item.network_fetch_count)
                            for item in outcomes
                        ),
                    )
                ),
                "git_materialized_bytes": git_materialized_bytes,
                "lifetime_materialized_total_status": (
                    "not_evaluable"
                    if int(
                        combined_attempt_usage.get(
                            "network_materialized_bytes_unknown_attempt_count",
                            0,
                        )
                    )
                    else "exact"
                ),
                "network_materialized_bytes_unknown_attempt_count": int(
                    combined_attempt_usage.get(
                        "network_materialized_bytes_unknown_attempt_count",
                        0,
                    )
                ),
                "attempt_counts": {
                    "historical": int(
                        historical_attempt_usage.get(
                            "attempt_count", 0
                        )
                    ),
                    "current": int(
                        current_attempt_usage.get("attempt_count", 0)
                    ),
                    "combined": int(
                        combined_attempt_usage.get(
                            "attempt_count", 0
                        )
                    ),
                },
                "git_materialized_bytes_by_origin": {
                    "historical": int(
                        (
                            historical_attempt_usage.get("usage")
                            if isinstance(
                                historical_attempt_usage.get("usage"),
                                Mapping,
                            )
                            else {}
                        ).get("network_materialized_bytes", 0)
                    ),
                    "current": int(
                        current_attempt_usage.get(
                            "network_materialized_bytes", 0
                        )
                    ),
                    "combined": int(
                        combined_attempt_usage.get(
                            "network_materialized_bytes", 0
                        )
                    ),
                },
                "git_materialized_byte_budget": (
                    budgets.max_git_materialized_bytes
                ),
                "classifications": classifications,
                "attempt_usage": attempt_usage,
                "outliers": outliers,
            },
            "cache": {
                "before_bytes": cache_before_bytes,
                "after_bytes": cache_after,
                "growth_bytes": cache_after - cache_before_bytes,
                "entries_before": len(cache_before_keys),
                "entries_after": len(cache_after_keys),
                "net_evictions": len(cache_before_keys - cache_after_keys),
                "target_bytes": budgets.cache_target_bytes,
                "hard_bytes": budgets.cache_hard_bytes,
            },
            "api": {
                "graphql_requests": int(
                    final_visibility["run_graphql_requests"]
                ),
                "graphql_points": int(
                    final_visibility["run_graphql_points"]
                ),
                "graphql_remaining": int(
                    final_visibility["run_graphql_remaining"]
                ),
                "initial_metadata": {
                    "graphql_requests": int(resolution.request_count),
                    "graphql_points": int(resolution.points_used),
                    "graphql_remaining": resolution.remaining,
                },
                "final_visibility": dict(final_visibility),
                "transports": transports,
            },
            "discovery": {
                "planned_sourcegraph_requests": int(
                    discovery_metrics.get("sourcegraph_query_packs", 0)
                ),
                "actual_sourcegraph_requests": int(
                    discovery_metrics.get(
                        "sourcegraph_requests_this_invocation", 0
                    )
                ),
                "cumulative_sourcegraph_requests": int(
                    discovery_metrics.get("sourcegraph_requests", 0)
                ),
                "planned_github_query_packs": int(
                    discovery_metrics.get("github_query_packs", 0)
                ),
                "actual_github_requests": int(
                    discovery_metrics.get(
                        "github_search_requests_this_invocation", 0
                    )
                ),
                "cumulative_github_requests": int(
                    discovery_metrics.get("github_search_requests", 0)
                ),
                "observations": int(
                    discovery_metrics.get("observation_count", 0)
                ),
                "certificates": len(
                    discovery_metrics.get("certificates", ())
                ),
                "gaps": len(discovery_metrics.get("gaps", ())),
                "queue_depth": int(
                    discovery_metrics.get("queue_depth", 0)
                ),
                "by_library": {
                    library_id: dict(values)
                    for library_id, values in sorted(
                        discovery_by_library.items()
                    )
                },
                "query_outliers": query_outliers[:10],
            },
            "citations": dict(self._citation_metrics),
            "publication": {
                "artifact_count": len(artifact_rows),
                "artifact_bytes": artifact_bytes,
                "max_artifact_bytes": max(
                    (
                        int(item.get("bytes", 0))
                        for item in artifact_rows
                    ),
                    default=0,
                ),
                "home_manifest_bytes": next(
                    (
                        int(item.get("bytes", 0))
                        for item in artifact_rows
                        if item.get("path") == "data/v2/manifest.json"
                    ),
                    0,
                ),
                "largest_artifacts": artifact_largest,
                "artifact_inventory": [
                    dict(item) for item in artifact_rows
                ],
            },
            "resources": {
                "max_rss_self_bytes": rss["self"],
                "max_rss_children_bytes": rss["children"],
                "max_rss_combined_upper_bytes": rss["combined_upper"],
                "max_rss_budget_bytes": budgets.max_rss_bytes,
                "within_rss_budget": (
                    rss["combined_upper"] <= budgets.max_rss_bytes
                ),
                "disk_free_bytes": disk.free,
                "disk_total_bytes": disk.total,
            },
        }

    @property
    def _publication_journal_path(self) -> Path:
        return self.state_path.parent / "publication-journal.json"

    def _write_publication_journal(self, **values: Any) -> None:
        _atomic_json(self._publication_journal_path, values)

    def _clear_publication_journal(self) -> None:
        self._publication_journal_path.unlink(missing_ok=True)

    def _live_v2_release_id(self) -> str | None:
        try:
            manifest = json.loads(
                (self.data_dir / "v2" / "manifest.json").read_text()
            )
            release_id = manifest["release"]["id"]
            return release_id if isinstance(release_id, str) else None
        except (FileNotFoundError, OSError, TypeError, ValueError, KeyError):
            return None

    def _run_base_release_id(self) -> str:
        """Return the immutable live base identity used by run resumption."""
        path = self.data_dir / "v2" / "manifest.json"
        if not path.exists():
            return NO_LIVE_V2_RELEASE
        try:
            manifest = json.loads(path.read_text())
            release_id = manifest["release"]["id"]
        except (OSError, TypeError, ValueError, KeyError) as exc:
            raise PipelineError(
                "live V2 manifest has no valid base release"
            ) from exc
        if (
            not isinstance(release_id, str)
            or not release_id
            or release_id != release_id.strip()
        ):
            raise PipelineError(
                "live V2 manifest has no valid base release"
            )
        return release_id

    def _restore_checkpoint_from_journal(
        self, journal: Mapping[str, Any]
    ) -> None:
        live = self.data_dir / "state-checkpoint"
        raw_backup = journal.get("checkpoint_backup")
        backup = Path(raw_backup) if isinstance(raw_backup, str) else None
        if backup is not None and backup.parent != self.data_dir:
            raise PipelineError("publication journal checkpoint path escaped data")
        if backup is not None and backup.exists():
            failed = self.data_dir / (
                ".state-checkpoint-recovery-failed-" + uuid.uuid4().hex
            )
            if live.exists():
                os.replace(live, failed)
            os.replace(backup, live)
            shutil.rmtree(failed, ignore_errors=True)
        elif journal.get("checkpoint_had_live") is False and live.exists():
            shutil.rmtree(live)

    def _recover_publication(self, state: StateDB) -> None:
        """Roll a power-interrupted two-tree publication forward or back.

        The V2 manifest is the external commit pointer. If it names the staged
        release, all content was already validated and installed manifest-last,
        so recovery completes state/checkpoint publication. Otherwise the
        provisional checkpoint is restored and the running task journal resumes.
        """
        path = self._publication_journal_path
        if not path.exists():
            return
        try:
            journal = json.loads(path.read_text())
        except (OSError, TypeError, ValueError) as exc:
            raise PipelineError("publication recovery journal is unreadable") from exc
        required = {"run_id", "release_id", "artifacts", "counters"}
        if not isinstance(journal, Mapping) or not required.issubset(journal):
            raise PipelineError("publication recovery journal is malformed")
        run_id = journal["run_id"]
        release_id = journal["release_id"]
        if self._live_v2_release_id() != release_id:
            if (self.data_dir / "v2" / "manifest.json").exists():
                _close_and_validate_v2(self.data_dir / "v2")
            self._restore_checkpoint_from_journal(journal)
            self._clear_publication_journal()
            return

        _close_and_validate_v2(self.data_dir / "v2")
        state.update_stage(
            run_id,
            "publication",
            status="complete",
            counters=journal["counters"],
        )
        state.finish_run(run_id, status="complete")
        state.record_release(
            release_id,
            run_id=run_id,
            state_txn=run_id,
            manifest_path="data/v2/manifest.json",
            artifacts=journal["artifacts"],
            validation={"valid": True, "errors": [], "recovered": True},
            status="published",
        )
        state.compact_operational_history()
        with tempfile.TemporaryDirectory(
            prefix=".state-checkpoint-recovery-",
            dir=self.data_dir,
        ) as temporary:
            staging = Path(temporary) / "state-checkpoint"
            state.export_checkpoint_shards(staging)
            _DirectorySwap(
                staging, self.data_dir / "state-checkpoint"
            ).install().commit()
        raw_backup = journal.get("checkpoint_backup")
        if isinstance(raw_backup, str):
            backup = Path(raw_backup)
            if backup.parent == self.data_dir:
                shutil.rmtree(backup, ignore_errors=True)
        for quarantine in self.data_dir.glob(".v2-superseded-*"):
            shutil.rmtree(quarantine, ignore_errors=True)
        self._clear_publication_journal()

    @classmethod
    def production(cls, **kwargs):
        from .http_transport import (
            DEFAULT_GITHUB_BUDGET,
            GitHubCodeSearchTransport,
            GitHubGraphQLTransport,
            RECONCILE_GITHUB_RETRY_WAIT_SECONDS,
            SourcegraphStreamTransport,
            TransportBudget,
            resolve_github_token,
        )
        budgets = kwargs.pop("budgets", RunBudgets.weekly())
        metadata_batch_size = kwargs.pop(
            "metadata_batch_size", METADATA_BATCH_SIZE
        )
        if (
            not isinstance(metadata_batch_size, int)
            or isinstance(metadata_batch_size, bool)
            or not 1 <= metadata_batch_size <= 100
        ):
            raise ValueError("invalid production metadata batch size")
        mode = kwargs.pop("mode", "refresh")
        if mode not in {"refresh", "reconcile"}:
            raise ValueError("invalid production collector mode")
        token = resolve_github_token()
        github_retry_wait_seconds = (
            RECONCILE_GITHUB_RETRY_WAIT_SECONDS
            if mode == "reconcile"
            else DEFAULT_GITHUB_BUDGET.max_total_retry_seconds
        )
        search_transport = GitHubCodeSearchTransport(
            token=token,
            budget=TransportBudget(
                budgets.max_github_search_requests,
                16 * 1024**2,
                2 * 1024**3,
                github_retry_wait_seconds,
            ),
        )
        graphql_transport = GitHubGraphQLTransport(
            token=token,
            budget=TransportBudget(
                max(100, budgets.max_graphql_points),
                16 * 1024**2,
                512 * 1024**2,
                600,
            ),
        )
        sourcegraph_transport = SourcegraphStreamTransport(
            budget=TransportBudget(
                budgets.max_sourcegraph_requests,
                128 * 1024**2,
                4 * 1024**3,
                600,
            ),
        )
        pipeline = cls(
            sourcegraph=SourcegraphDiscovery(sourcegraph_transport),
            github_search=GitHubCodeSearch(
                search_transport, min_interval=0, max_retries=0
            ),
            metadata=GitHubGraphQLClient(
                graphql_transport,
                batch_size=metadata_batch_size,
                point_budget=budgets.max_graphql_points,
                minimum_remaining=budgets.min_graphql_remaining,
                min_interval=0,
                max_retries=0,
            ),
            **kwargs,
        )
        pipeline._transport_metrics = {
            "github_code_search": search_transport,
            "github_graphql": graphql_transport,
            "sourcegraph": sourcegraph_transport,
        }
        return pipeline

    def _charge_prior_discovery_usage(self, state, run_id: str) -> dict[str, Any]:
        usage = _durable_discovery_request_usage(state, run_id)
        transport_names = {
            "github-code-search": "github_code_search",
            "sourcegraph": "sourcegraph",
        }
        for source, transport_name in transport_names.items():
            transport = self._transport_metrics.get(transport_name)
            charge = getattr(transport, "charge_prior_requests", None)
            if callable(charge):
                try:
                    charge(int(usage["sources"][source]["charged"]))
                except Exception as exc:
                    raise BudgetExceeded(
                        "%s durable request usage exhausts its budget"
                        % source
                    ) from exc
        return usage

    def _transport_usage_snapshot(
        self,
        source: str,
    ) -> dict[str, int] | None:
        transport_name = {
            "github-code-search": "github_code_search",
            "sourcegraph": "sourcegraph",
        }.get(source)
        transport = self._transport_metrics.get(transport_name or "")
        snapshot = getattr(transport, "metrics_snapshot", None)
        if not callable(snapshot):
            return None
        metrics = snapshot()
        fields = (
            "operations",
            "attempts",
            "retries",
            "rate_limited_attempts",
            "server_error_attempts",
            "network_error_attempts",
            "budget_rejections",
        )
        return {field: int(metrics.get(field, 0) or 0) for field in fields}

    def _record_transport_task_usage(
        self,
        state,
        *,
        run_id: str,
        task_id: int,
        attempt: int,
        source: str,
        result_status: str,
        before: Mapping[str, int] | None,
    ) -> None:
        after = self._transport_usage_snapshot(source)
        if before is None or after is None:
            return
        delta = {
            field: max(0, int(after[field]) - int(before[field]))
            for field in after
        }
        state.record_network_task_usage(
            run_id=run_id,
            task_id=task_id,
            attempt=attempt,
            source=source,
            result_status=result_status,
            operation_count=delta["operations"],
            request_attempt_count=delta["attempts"],
            retry_count=delta["retries"],
            rate_limited_attempts=delta["rate_limited_attempts"],
            server_error_attempts=delta["server_error_attempts"],
            network_error_attempts=delta["network_error_attempts"],
            budget_rejections=delta["budget_rejections"],
        )

    def _check_time(self, started: float, budgets: RunBudgets):
        if self.clock() - started > budgets.max_wall_seconds:
            raise BudgetExceeded("wall-time budget exceeded")
        if _rss_usage_bytes()["combined_upper"] > budgets.max_rss_bytes:
            raise BudgetExceeded("RSS budget exceeded")

    def _check_slo(
        self,
        *,
        mode: str,
        scans: int,
        started: float,
        budgets: RunBudgets,
        run_class: str | None = None,
    ) -> None:
        self._check_time(started, budgets)
        profile = _slo_profile(
            mode,
            scans,
            budgets,
            run_class=run_class,
        )
        if self.clock() - started > profile["ceiling_seconds"]:
            raise BudgetExceeded(
                "%s ceiling exceeded" % profile["class"].replace("_", "-")
            )

    def _restore_state_checkpoint_if_needed(self) -> bool:
        """Atomically restore missing local state from the public checkpoint.

        Planning intentionally remains read-only and never invokes this path.
        A networked run restores before planning so a valid last-good
        fingerprint cannot be mistaken for cold state.  A present but invalid
        checkpoint fails closed before any discovery adapter is called.  The
        latest published release in the checkpoint must also name the live V2
        manifest; otherwise a stale or partially committed checkpoint could
        incorrectly make a cold checkout look reusable.
        """
        if self.state_path.exists():
            return False
        checkpoint = self.data_dir / "state-checkpoint"
        if not checkpoint.exists():
            return False
        if not checkpoint.is_dir():
            raise PipelineError("state checkpoint validation failed")

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".%s.restore-" % self.state_path.name,
            suffix=".sqlite3",
            dir=self.state_path.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        companions = (
            temporary,
            Path(str(temporary) + "-wal"),
            Path(str(temporary) + "-shm"),
        )
        try:
            live_release_id = self._run_base_release_id()
            if live_release_id == NO_LIVE_V2_RELEASE:
                raise ValueError(
                    "checkpoint has no live V2 manifest release"
                )
            with StateDB(temporary) as restored:
                restored.import_checkpoint(checkpoint)
                if restored.integrity_check() != "ok":
                    raise ValueError("restored checkpoint state is not integral")
                row = restored.connection.execute(
                    """
                    SELECT fingerprints_json FROM runs
                    WHERE status='complete'
                    ORDER BY finished_at DESC, created_at DESC
                    LIMIT 1
                    """
                ).fetchone()
                if row is None:
                    raise ValueError(
                        "checkpoint has no completed fingerprint state"
                    )
                FingerprintManifest.from_dict(
                    json.loads(row["fingerprints_json"])
                )
                release = restored.connection.execute(
                    """
                    SELECT release_id, manifest_path
                    FROM releases
                    WHERE status='published'
                    ORDER BY published_at DESC, created_at DESC, release_id DESC
                    LIMIT 1
                    """
                ).fetchone()
                if (
                    release is None
                    or release["release_id"] != live_release_id
                    or release["manifest_path"] != "data/v2/manifest.json"
                ):
                    raise ValueError(
                        "checkpoint published release differs from live V2"
                    )
            os.replace(temporary, self.state_path)
        except (
            OSError,
            RuntimeError,
            ValueError,
            KeyError,
            PipelineError,
        ) as exc:
            raise PipelineError("state checkpoint validation failed") from exc
        finally:
            for path in companions:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
        return True

    def _discover(
        self, state, run_id, libraries, mode, budgets, *, run_deadline=None
    ):
        if self.sourcegraph is None or self.github_search is None:
            raise PipelineError("network discovery adapters are not configured")
        github_ids = (
            {lib["id"] for lib in libraries}
            if mode == "reconcile"
            else _github_lane_ids(state, libraries)
        )
        github_ids.update(self._active_plan.invalidation.discover)
        github_is_authoritative = (
            mode == "reconcile"
            or github_ids == {lib["id"] for lib in libraries}
        )
        required_sources = (
            ("github-code-search",)
            if github_is_authoritative
            else ("sourcegraph",)
        )
        advisory_sources = (
            ("sourcegraph",)
            if github_is_authoritative
            else ()
        )
        results = []
        declared_signal_lanes = sum(
            len(signal_specs(lib)) for lib in libraries
        )
        task_specs = []
        github_member_query_index = {
            (lib["id"], member.signal_id): member.github_query
            for lib in libraries
            for member in signal_specs(lib)
        }
        for lib in libraries:
            for pack in query_packs(lib):
                sourcegraph_fp = sourcegraph_query_fingerprint(pack)
                task_specs.append(
                    {
                        "source": "sourcegraph",
                        "library_id": lib["id"],
                        "signal_id": pack.signal_id,
                        "query": pack.sourcegraph_query,
                        "query_fingerprint": sourcegraph_fp,
                        "extensions": [],
                        "pack_kind": pack.kind,
                        "member_signal_ids": list(
                            pack.member_signal_ids
                        ),
                    }
                )
                if lib["id"] in github_ids:
                    github_fp = github_query_fingerprint(pack)
                    task_specs.append(
                        {
                            "source": "github-code-search",
                            "library_id": lib["id"],
                            "signal_id": pack.signal_id,
                            "query": pack.github_query,
                            "query_fingerprint": github_fp,
                            "extensions": list(pack.extensions),
                            "pack_kind": pack.kind,
                            "member_signal_ids": list(
                                pack.member_signal_ids
                            ),
                        }
                    )
        sourcegraph_planned = sum(
            spec["source"] == "sourcegraph" for spec in task_specs
        )
        github_planned = sum(
            spec["source"] == "github-code-search"
            for spec in task_specs
        )
        if sourcegraph_planned > budgets.max_sourcegraph_requests:
            raise BudgetExceeded("Sourcegraph request budget exceeded")
        if github_planned > budgets.max_github_search_requests:
            raise BudgetExceeded("GitHub search request budget exceeded")

        task_ids = []
        task_keys = []
        for spec in task_specs:
            source_key = (
                "sg"
                if spec["source"] == "sourcegraph"
                else "github"
            )
            task_key = "%s:%s:%s" % (
                source_key,
                spec["library_id"],
                spec["query_fingerprint"],
            )
            task_keys.append(task_key)
            task_ids.append(
                state.enqueue_task(
                    run_id,
                    "discovery-query",
                    task_key,
                    library_id=spec["library_id"],
                    payload=spec,
                    max_attempts=3,
                )
            )
        state.supersede_tasks(
            run_id,
            "discovery-query",
            keep_task_keys=task_keys,
            reason="discovery-query-plan-updated",
        )

        sourcegraph_requests = github_query_packs = github_requests = 0
        sourcegraph_requests_this_invocation = 0
        github_requests_this_invocation = 0
        reused_tasks = 0
        worker = "coordinator:%s:discovery" % run_id
        for spec, task_id in zip(task_specs, task_ids):
            if run_deadline is not None and self.clock() >= run_deadline:
                raise BudgetExceeded(
                    "wall-time budget exhausted during discovery"
                )
            document = _completed_task_document(state, task_id)
            if document is not None:
                reused_tasks += 1
                task_reused = True
            else:
                task_reused = False
                leased = state.lease_task_by_id(
                    task_id,
                    worker=worker,
                    lease_seconds=NETWORK_TASK_LEASE_SECONDS,
                )
                if leased is None:
                    raise PipelineError(
                        "discovery query task is not leaseable"
                    )
                usage_before = self._transport_usage_snapshot(
                    spec["source"]
                )
                try:
                    def run_discovery_task():
                        adapter = (
                            self.sourcegraph
                            if spec["source"] == "sourcegraph"
                            else self.github_search
                        )
                        kwargs = {
                            "library_id": spec["library_id"],
                            "signal_id": spec["signal_id"],
                            "query": spec["query"],
                            "query_fingerprint": spec[
                                "query_fingerprint"
                            ],
                            "deadline_monotonic": run_deadline,
                        }
                        if spec["source"] == "github-code-search":
                            kwargs["extensions"] = tuple(
                                spec["extensions"]
                            )
                            member_queries = tuple(
                                github_member_query_index[
                                    (spec["library_id"], member_signal_id)
                                ]
                                for member_signal_id in spec[
                                    "member_signal_ids"
                                ]
                            )
                            if (
                                " OR ".join(member_queries)
                                != spec["query"]
                            ):
                                raise PipelineError(
                                    "GitHub member queries do not reproduce "
                                    "the logical discovery pack"
                                )
                            kwargs["member_queries"] = member_queries
                            kwargs["member_signal_ids"] = tuple(
                                spec["member_signal_ids"]
                            )
                        result = adapter.search(**kwargs)
                        _assert_discovery_task_result(result, spec)
                        result = dataclasses.replace(
                            result,
                            certificate=dataclasses.replace(
                                result.certificate,
                                metrics={
                                    **result.certificate.metrics,
                                    "query_pack_kind": spec["pack_kind"],
                                    "member_signal_ids": ",".join(
                                        spec["member_signal_ids"]
                                    ),
                                    "member_count": len(
                                        spec["member_signal_ids"]
                                    ),
                                },
                            ),
                        )
                        _assert_discovery_task_result(result, spec)
                        if (
                            not result.certificate.complete
                            and spec["source"] in required_sources
                        ):
                            # Preserve the diagnostic certificate but do not
                            # complete the task. The outer lease handler
                            # requeues it, allowing a reviewed retry without
                            # running the rest of an already-doomed epoch.
                            _record_coverage(state, run_id, result)
                            codes = sorted(
                                {
                                    gap.code
                                    for gap in result.certificate.gaps
                                }
                            )
                            raise PipelineError(
                                "%s discovery coverage incomplete for %s: %s"
                                % (
                                    spec["source"],
                                    spec["library_id"],
                                    ",".join(codes) or "incomplete",
                                )
                            )
                        return _discovery_result_to_task_result(result)

                    def run_discovery_task_with_usage():
                        try:
                            return run_discovery_task()
                        except BaseException:
                            self._record_transport_task_usage(
                                state,
                                run_id=run_id,
                                task_id=task_id,
                                attempt=int(leased["attempts"]),
                                source=spec["source"],
                                result_status="failed",
                                before=usage_before,
                            )
                            raise

                    document = _complete_journaled_network_task(
                        state,
                        self.state_path,
                        task_id,
                        worker,
                        run_discovery_task_with_usage,
                        before_complete=lambda: (
                            self._record_transport_task_usage(
                                state,
                                run_id=run_id,
                                task_id=task_id,
                                attempt=int(leased["attempts"]),
                                source=spec["source"],
                                result_status="complete",
                                before=usage_before,
                            )
                        ),
                    )
                except BaseException:
                    try:
                        state.fail_task(
                            task_id,
                            worker=worker,
                            error_code="discovery-query-failed",
                            retry=True,
                        )
                    except RuntimeError:
                        pass
                    raise
            result = _discovery_result_from_task_result(document)
            _assert_discovery_task_result(result, spec)
            if run_deadline is not None and self.clock() >= run_deadline:
                raise BudgetExceeded(
                    "wall-time budget exhausted during discovery"
                )
            results.append(result)
            _record_coverage(state, run_id, result)
            if spec["source"] == "sourcegraph":
                sourcegraph_requests += 1
                if not task_reused:
                    sourcegraph_requests_this_invocation += 1
            else:
                github_query_packs += 1
                task_request_count = max(
                    1,
                    int(
                        result.certificate.metrics.get(
                            "request_count", 0
                        )
                        or 0
                    ),
                )
                github_requests += task_request_count
                if not task_reused:
                    github_requests_this_invocation += task_request_count
                if (
                    github_requests
                    > budgets.max_github_search_requests
                ):
                    raise BudgetExceeded(
                        "GitHub search request budget exceeded"
                    )
        composite = combine_discovery_results(
            (),
            results,
            required_sources=required_sources,
            advisory_sources=advisory_sources,
        )
        if not composite.complete:
            raise PipelineError(
                "discovery coverage incomplete: %s" % ", ".join(composite.reasons)
            )
        certificates = _carry_forward_coverage_certificates(
            state,
            libraries,
            (item.to_dict() for item in composite.certificates),
        )
        durable_usage = _durable_discovery_request_usage(state, run_id)
        actual_github_requests = int(
            durable_usage["sources"]["github-code-search"]["charged"]
        )
        actual_sourcegraph_requests = int(
            durable_usage["sources"]["sourcegraph"]["charged"]
        )
        if actual_github_requests > budgets.max_github_search_requests:
            raise BudgetExceeded("GitHub search request budget exceeded")
        if actual_sourcegraph_requests > budgets.max_sourcegraph_requests:
            raise BudgetExceeded("Sourcegraph request budget exceeded")
        return composite.observations, {
            "declared_signal_lanes": declared_signal_lanes,
            "sourcegraph_query_packs": sourcegraph_requests,
            "sourcegraph_requests": sourcegraph_requests,
            "sourcegraph_requests_this_invocation": (
                sourcegraph_requests_this_invocation
            ),
            "github_query_packs": github_query_packs,
            "github_search_requests": github_requests,
            "github_search_requests_this_invocation": (
                github_requests_this_invocation
            ),
            "github_search_request_attempts": actual_github_requests,
            "sourcegraph_request_attempts": actual_sourcegraph_requests,
            "durable_request_usage": durable_usage,
            "github_signal_lanes": github_query_packs,
            "packed_sourcegraph_lanes_saved": (
                declared_signal_lanes - sourcegraph_requests
            ),
            "github_libraries": sorted(github_ids),
            "tasks_total": len(task_ids),
            "tasks_completed": len(results),
            "tasks_reused": reused_tasks,
            "queue_depth": state.connection.execute(
                """
                SELECT COUNT(*) FROM tasks
                WHERE run_id=? AND stage='discovery-query'
                  AND status!='complete'
                """,
                (run_id,),
            ).fetchone()[0],
            "certificates": certificates,
        }

    def _resolve_metadata(
        self,
        state,
        observations,
        legacy,
        state_known,
        *,
        run_id=None,
        budgets=None,
        run_deadline=None,
        force_refresh=False,
        reuse_completed_epoch=False,
        preseeded_epoch_contract=None,
        resume_incomplete_fresh_epoch=False,
        resume_fresh_metadata_epoch=None,
        post_refresh_privacy_control=None,
        final_visibility_privacy_control=None,
    ):
        if self.metadata is None:
            raise PipelineError("GitHub metadata adapter is not configured")
        resumed_parts = []
        if run_id is not None and reuse_completed_epoch:
            rows = list(state.connection.execute(
                """
                SELECT task_id, task_key, status FROM tasks
                WHERE run_id=? AND stage='github-metadata-batch'
                ORDER BY task_id
                """,
                (run_id,),
            ))
            # A final-visibility failure forces a fresh metadata epoch.  Keep
            # the earlier preseeded epoch as immutable history, but never
            # merge two complete epochs into one resolution on a later
            # resume.  Fresh task keys carry a random epoch prefix; select
            # only the newest such exact group when it exists.
            fresh_rows = [
                row for row in rows
                if str(row["task_key"]).startswith("fresh:")
            ]
            if fresh_rows:
                newest_epoch = str(fresh_rows[-1]["task_key"]).split(
                    ":", 2
                )[1]
                rows = [
                    row for row in fresh_rows
                    if str(row["task_key"]).split(":", 2)[1]
                    == newest_epoch
                ]
            if rows and all(row["status"] == "complete" for row in rows):
                resumed_parts = [
                    _metadata_result_from_task_result(
                        _completed_task_document(
                            state, int(row["task_id"])
                        )
                    )
                    for row in rows
                ]
        lookups = [
            RepositoryLookup(node_id=node_id, full_name=name)
            for node_id, name in state_known
        ]
        known_names = {name.casefold() for _node, name in state_known}
        names = set(legacy)
        names.update(observation.repo_full_name for observation in observations)
        lookups.extend(
            RepositoryLookup(full_name=name)
            for name in sorted(names)
            if name.casefold() not in known_names
        )
        unique_lookups = {
            lookup.key: lookup for lookup in lookups
        }
        lookups = [
            unique_lookups[key] for key in sorted(unique_lookups)
        ]
        rejected_final_visibility_node = None
        if final_visibility_privacy_control is not None:
            if run_id is None or post_refresh_privacy_control is None:
                raise PipelineError(
                    "final-visibility privacy metadata context changed"
                )
            rejected_final_visibility_node = (
                _phase8_final_visibility_rejected_node(
                    state, run_id, final_visibility_privacy_control
                )
            )
        if post_refresh_privacy_control is not None:
            if (
                run_id is None
                or not force_refresh
                or not resume_incomplete_fresh_epoch
                or resume_fresh_metadata_epoch
                != post_refresh_privacy_control.get(
                    "fresh_metadata_epoch"
                )
            ):
                raise PipelineError(
                    "post-refresh metadata recovery context changed"
                )
            certified_epoch = post_refresh_privacy_control[
                "fresh_metadata_epoch"
            ]
            certified_rows = list(state.connection.execute(
                """
                SELECT task_id,task_key,status,payload_json,result_json
                FROM tasks
                WHERE run_id=? AND stage='github-metadata-batch'
                  AND task_key LIKE ?
                ORDER BY task_id
                """,
                (run_id, "fresh:" + certified_epoch + ":%"),
            ))
            if (
                len(certified_rows)
                != post_refresh_privacy_control[
                    "fresh_metadata_batch_count"
                ]
                or not certified_rows
                or any(
                    row["status"] != "complete"
                    for row in certified_rows
                )
            ):
                raise PipelineError(
                    "post-refresh certified metadata epoch changed"
                )
            certified_lookups = []
            certified_parts = []
            repository_proofs_by_requested_name = {}
            for row in certified_rows:
                try:
                    payload = json.loads(row["payload_json"] or "{}")
                    raw_lookups = payload["lookups"]
                    document = json.loads(row["result_json"] or "{}")
                except (
                    KeyError,
                    TypeError,
                    json.JSONDecodeError,
                ) as exc:
                    raise PipelineError(
                        "post-refresh certified metadata epoch is malformed"
                    ) from exc
                if (
                    payload.get("version") != 1
                    or not isinstance(raw_lookups, list)
                ):
                    raise PipelineError(
                        "post-refresh certified metadata epoch is malformed"
                    )
                try:
                    certified_lookups.extend(
                        RepositoryLookup(
                            node_id=item.get("node_id"),
                            full_name=item.get("full_name"),
                        )
                        for item in raw_lookups
                    )
                    certified_parts.append(
                        _metadata_result_from_task_result(document)
                    )
                except (AttributeError, TypeError, ValueError) as exc:
                    raise PipelineError(
                        "post-refresh certified metadata epoch is malformed"
                    ) from exc
                for repository in document.get("repositories", []):
                    requested_name = repository.get(
                        "requested_full_name"
                    )
                    if requested_name is not None:
                        repository_proofs_by_requested_name[
                            str(requested_name).casefold()
                        ] = {
                            "task_id": int(row["task_id"]),
                            "task_key_sha256": hashlib.sha256(
                                str(row["task_key"]).encode("utf-8")
                            ).hexdigest(),
                            "repository": repository,
                        }
            certified_by_name = {
                str(lookup.full_name).casefold(): lookup
                for lookup in certified_lookups
            }
            current_by_name = {
                str(lookup.full_name).casefold(): lookup
                for lookup in lookups
            }
            if (
                len(certified_lookups) != len(certified_by_name)
                or len(lookups) != len(current_by_name)
                or set(certified_by_name) != set(current_by_name)
            ):
                raise PipelineError(
                    "post-refresh metadata lookup universe changed"
                )
            changed_identity_names = {
                name for name in certified_by_name
                if certified_by_name[name].key
                != current_by_name[name].key
            }
            if rejected_final_visibility_node is not None:
                certified_final_names = {
                    name for name in changed_identity_names
                    if (
                        certified_by_name[name].node_id
                        == rejected_final_visibility_node
                        and current_by_name[name].node_id is None
                    )
                }
                if len(certified_final_names) != 1:
                    raise PipelineError(
                        "final-visibility privacy metadata identity changed"
                    )
                changed_identity_names -= certified_final_names
            repositories = [
                repository
                for part in certified_parts
                for repository in part.repositories
            ]
            result_by_requested_name = {
                str(repository.requested_full_name).casefold(): repository
                for repository in repositories
            }
            missing_documents = []
            for name in changed_identity_names:
                prior = certified_by_name[name]
                current = current_by_name[name]
                repository = result_by_requested_name.get(name)
                if repository is None:
                    raise PipelineError(
                        "post-refresh metadata identity proof changed"
                    )
                if prior.node_id is None:
                    valid = (
                        current.node_id == repository.node_id
                        and repository.publishable
                    )
                else:
                    valid = (
                        current.node_id is None
                        and repository.requested_node_id == prior.node_id
                        and repository.status == "missing"
                        and not repository.explicitly_public
                    )
                    if valid:
                        proof = repository_proofs_by_requested_name.get(name)
                        if proof is None:
                            valid = False
                        else:
                            missing_documents.append(proof)
                if not valid:
                    raise PipelineError(
                        "post-refresh metadata identity proof changed"
                    )
            if (
                _canonical_sha256(missing_documents)
                != post_refresh_privacy_control[
                    "fresh_missing_metadata_proof_sha256"
                ]
                or _canonical_sha256([
                    document["repository"]["requested_node_id"]
                    for document in missing_documents
                ])
                != post_refresh_privacy_control[
                    "additional_purged_repository_nodes_sha256"
                ]
            ):
                raise PipelineError(
                    "post-refresh missing metadata proof changed"
                )
            resumed_parts = certified_parts
        if preseeded_epoch_contract is not None:
            if not reuse_completed_epoch or not resumed_parts:
                raise PipelineError(
                    "preseeded GitHub metadata epoch is incomplete"
                )
            metadata_rows = list(state.connection.execute(
                """
                SELECT task_key, payload_json, result_json
                FROM tasks
                WHERE run_id=? AND stage='github-metadata-batch'
                  AND status='complete'
                ORDER BY task_id
                """,
                (run_id,),
            ))
            seeded_lookups = []
            for row in metadata_rows:
                try:
                    payload = json.loads(row["payload_json"])
                    raw_lookups = payload["lookups"]
                except (
                    KeyError,
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                ) as exc:
                    raise PipelineError(
                        "preseeded GitHub metadata payload is malformed"
                    ) from exc
                if payload.get("version") != 1 or not isinstance(
                    raw_lookups, list
                ):
                    raise PipelineError(
                        "preseeded GitHub metadata payload is malformed"
                    )
                seeded_lookups.extend(
                    RepositoryLookup(
                        node_id=item.get("node_id"),
                        full_name=item.get("full_name"),
                    )
                    for item in raw_lookups
                )
            task_universe = [
                {
                    "task_key": str(row["task_key"]),
                    "payload": json.loads(row["payload_json"]),
                }
                for row in metadata_rows
            ]
            result_universe = [
                {
                    "task_key": str(row["task_key"]),
                    "result_sha256": hashlib.sha256(
                        str(row["result_json"]).encode("utf-8")
                    ).hexdigest(),
                }
                for row in metadata_rows
            ]
            expected_keys = {lookup.key for lookup in seeded_lookups}
            actual_keys = [
                repository.request_key
                for part in resumed_parts
                for repository in part.repositories
            ]
            if (
                len(seeded_lookups) != len(expected_keys)
                or len(actual_keys) != len(set(actual_keys))
                or set(actual_keys) != expected_keys
                or preseeded_epoch_contract["task_count"]
                != len(metadata_rows)
                or preseeded_epoch_contract["lookup_count"]
                != len(seeded_lookups)
                or preseeded_epoch_contract["task_universe_sha256"]
                != hashlib.sha256(
                    fingerprint_json(task_universe).encode("utf-8")
                ).hexdigest()
                or preseeded_epoch_contract["result_universe_sha256"]
                != hashlib.sha256(
                    fingerprint_json(result_universe).encode("utf-8")
                ).hexdigest()
                or preseeded_epoch_contract["input_context_sha256"]
                != _metadata_input_context_sha256(
                    observations,
                    legacy,
                    state_known,
                )
            ):
                raise PipelineError(
                    "preseeded GitHub metadata epoch changed its exact "
                    "lookup/task/result universe"
                )
            lookups = seeded_lookups
        if resumed_parts:
            resolution = GraphQLResolution(
                repositories=tuple(
                    repository
                    for part in resumed_parts
                    for repository in part.repositories
                ),
                errors=tuple(
                    error
                    for part in resumed_parts
                    for error in part.errors
                ),
                request_count=sum(
                    part.request_count for part in resumed_parts
                ),
                points_used=sum(
                    part.points_used for part in resumed_parts
                ),
                remaining=min(
                    part.remaining for part in resumed_parts
                ),
                reset_at=next(
                    (
                        part.reset_at
                        for part in reversed(resumed_parts)
                        if part.reset_at is not None
                    ),
                    None,
                ),
            )
            self._metadata_task_metrics = {
                "tasks_total": len(resumed_parts),
                "tasks_completed": len(resumed_parts),
                "tasks_reused": len(resumed_parts),
                "queue_depth": 0,
            }
        elif run_id is None:
            try:
                resolution = self.metadata.resolve(
                    lookups,
                    deadline_monotonic=run_deadline,
                )
            except TypeError as exc:
                if "deadline_monotonic" not in str(exc):
                    raise
                resolution = self.metadata.resolve(lookups)
            self._metadata_task_metrics = {
                "tasks_total": 0,
                "tasks_completed": 0,
                "tasks_reused": 0,
                "queue_depth": 0,
            }
        else:
            batch_size = self._metadata_batch_size()
            freshness_epoch = uuid.uuid4().hex if force_refresh else None
            resumed_fresh_rows = []
            if force_refresh and resume_incomplete_fresh_epoch:
                all_fresh_rows = list(state.connection.execute(
                    """
                    SELECT task_key,status FROM tasks
                    WHERE run_id=? AND stage='github-metadata-batch'
                      AND task_key LIKE 'fresh:%'
                    ORDER BY task_id
                    """,
                    (run_id,),
                ))
                if all_fresh_rows:
                    freshness_epoch = (
                        str(resume_fresh_metadata_epoch)
                        if resume_fresh_metadata_epoch is not None
                        else str(all_fresh_rows[-1]["task_key"]).split(
                            ":", 2
                        )[1]
                    )
                    resumed_fresh_rows = [
                        row for row in all_fresh_rows
                        if str(row["task_key"]).split(":", 2)[1]
                        == freshness_epoch
                    ]
                    if not resumed_fresh_rows:
                        raise PipelineError(
                            "reviewed fresh metadata recovery epoch disappeared"
                        )
            batches = [
                lookups[offset:offset + batch_size]
                for offset in range(0, len(lookups), batch_size)
            ]
            task_specs = []
            for ordinal, batch in enumerate(batches):
                payload = {
                    "version": 1,
                    "lookups": [
                        {
                            "node_id": lookup.node_id,
                            "full_name": lookup.full_name,
                        }
                        for lookup in batch
                    ],
                }
                payload_fp = fingerprint(
                    "github-metadata-task", payload
                )
                task_key = "batch:%06d:%s" % (
                    ordinal,
                    payload_fp[:32],
                )
                if freshness_epoch is not None:
                    task_key = "fresh:%s:%s" % (
                        freshness_epoch[:16],
                        task_key,
                    )
                task_specs.append((task_key, payload))
            task_keys = [task_key for task_key, _payload in task_specs]
            if resumed_fresh_rows and (
                {str(row["task_key"]) for row in resumed_fresh_rows}
                != set(task_keys)
                or not all(
                    row["status"] in {"complete", "pending"}
                    for row in resumed_fresh_rows
                )
            ):
                raise PipelineError(
                    "reviewed partial fresh metadata epoch changed"
                )
            task_ids = [
                state.enqueue_task(
                    run_id,
                    "github-metadata-batch",
                    task_key,
                    payload=payload,
                    max_attempts=3,
                )
                for task_key, payload in task_specs
            ]
            state.supersede_tasks(
                run_id,
                "github-metadata-batch",
                keep_task_keys=task_keys,
                reason="github-metadata-plan-updated",
            )
            parts = []
            reused = 0
            worker = "coordinator:%s:metadata" % run_id
            for batch, task_id in zip(batches, task_ids):
                if (
                    run_deadline is not None
                    and self.clock() >= run_deadline
                ):
                    raise BudgetExceeded(
                        "wall-time budget exhausted during metadata"
                    )
                document = _completed_task_document(state, task_id)
                if document is not None:
                    reused += 1
                else:
                    journal_budget = _graphql_journal_budget(
                        state, run_id
                    )
                    prior_points = int(journal_budget["points_used"])
                    prior_remaining = journal_budget["remaining"]
                    prior_reset = journal_budget["reset_at"]
                    if (
                        budgets is not None
                        and prior_points + 1
                        > budgets.max_graphql_points
                    ):
                        raise BudgetExceeded(
                            "same-run GitHub GraphQL point budget would "
                            "be exceeded"
                        )
                    if (
                        budgets is not None
                        and prior_remaining is not None
                        and int(prior_remaining) - 1
                        < budgets.min_graphql_remaining
                    ):
                        raise BudgetExceeded(
                            "same-run GitHub GraphQL remaining-quota "
                            "reserve would be crossed"
                        )
                    restore_budget = getattr(
                        self.metadata, "restore_run_budget", None
                    )
                    if callable(restore_budget):
                        restore_budget(
                            points_spent=prior_points,
                            remaining=prior_remaining,
                            reset_at=prior_reset,
                        )
                    leased = state.lease_task_by_id(
                        task_id,
                        worker=worker,
                        lease_seconds=NETWORK_TASK_LEASE_SECONDS,
                    )
                    if leased is None:
                        raise PipelineError(
                            "GitHub metadata task is not leaseable"
                        )
                    try:
                        def run_metadata_task():
                            try:
                                part = self.metadata.resolve(
                                    batch,
                                    deadline_monotonic=run_deadline,
                                )
                            except TypeError as exc:
                                if "deadline_monotonic" not in str(exc):
                                    raise
                                part = self.metadata.resolve(batch)
                            expected_keys = {
                                lookup.key for lookup in batch
                            }
                            actual_keys = {
                                item.request_key
                                for item in part.repositories
                            }
                            if actual_keys != expected_keys:
                                raise PipelineError(
                                    "GitHub metadata batch did not exactly "
                                    "cover its lookups"
                                )
                            return _metadata_result_to_task_result(part)

                        document = _complete_journaled_network_task(
                            state,
                            self.state_path,
                            task_id,
                            worker,
                            run_metadata_task,
                        )
                    except BaseException:
                        try:
                            state.fail_task(
                                task_id,
                                worker=worker,
                                error_code="github-metadata-batch-failed",
                                retry=True,
                            )
                        except RuntimeError:
                            pass
                        raise
                part = _metadata_result_from_task_result(document)
                expected_keys = {lookup.key for lookup in batch}
                if {
                    item.request_key for item in part.repositories
                } != expected_keys:
                    raise PipelineError(
                        "journaled GitHub metadata batch does not match "
                        "its task"
                    )
                parts.append(part)
                cumulative_budget = _graphql_journal_budget(state, run_id)
                if budgets is not None and int(
                    cumulative_budget["points_used"]
                ) > budgets.max_graphql_points:
                    raise BudgetExceeded(
                        "GitHub GraphQL point budget exceeded"
                    )
                if (
                    budgets is not None
                    and part.remaining < budgets.min_graphql_remaining
                ):
                    raise BudgetExceeded(
                        "GitHub GraphQL remaining-quota reserve crossed"
                    )
            resolution = GraphQLResolution(
                repositories=tuple(
                    repository
                    for part in parts
                    for repository in part.repositories
                ),
                errors=tuple(
                    error for part in parts for error in part.errors
                ),
                request_count=sum(
                    part.request_count for part in parts
                ),
                points_used=sum(part.points_used for part in parts),
                remaining=(
                    min(part.remaining for part in parts)
                    if parts
                    else int(
                        getattr(self.metadata, "remaining", None)
                        or (
                            budgets.min_graphql_remaining
                            if budgets is not None
                            else 0
                        )
                    )
                ),
                reset_at=next(
                    (
                        part.reset_at
                        for part in reversed(parts)
                        if part.reset_at is not None
                    ),
                    None,
                ),
            )
            self._metadata_task_metrics = {
                "tasks_total": len(task_ids),
                "tasks_completed": len(parts),
                "tasks_reused": reused,
                "queue_depth": state.connection.execute(
                    """
                    SELECT COUNT(*) FROM tasks
                    WHERE run_id=? AND stage='github-metadata-batch'
                      AND status!='complete'
                    """,
                    (run_id,),
                ).fetchone()[0],
            }
        if run_deadline is not None and self.clock() >= run_deadline:
            raise BudgetExceeded("wall-time budget exhausted during metadata")
        if not resolution.complete:
            raise PipelineError("GitHub metadata contains unresolved partial errors")
        if rejected_final_visibility_node is not None:
            rejected_metadata = [
                repository for repository in resolution.repositories
                if (
                    repository.node_id == rejected_final_visibility_node
                    or repository.requested_node_id
                    == rejected_final_visibility_node
                )
            ]
            if (
                len(rejected_metadata) != 1
                or not rejected_metadata[0].publishable
            ):
                raise PipelineError(
                    "final-visibility privacy metadata proof changed"
                )
            resolution = dataclasses.replace(
                resolution,
                repositories=tuple(
                    repository for repository in resolution.repositories
                    if repository not in rejected_metadata
                ),
            )

        by_requested_name = {}
        by_node = {}
        publishable = {}
        publishable_folded = {}
        unresolved = 0

        def metadata_identity(item):
            return (
                item.node_id or item.requested_node_id,
                (
                    item.full_name.casefold()
                    if isinstance(item.full_name, str)
                    else None
                ),
            )

        def bind_metadata_alias(index, key, item, *, kind):
            if not isinstance(key, str) or not key:
                return
            existing = index.get(key)
            if (
                existing is not None
                and metadata_identity(existing) != metadata_identity(item)
            ):
                raise PipelineError(
                    "GitHub metadata %s collision for %s" % (kind, key)
                )
            index[key] = item

        for item in resolution.repositories:
            if item.requested_full_name:
                bind_metadata_alias(
                    by_requested_name,
                    item.requested_full_name.casefold(),
                    item,
                    kind="requested-name",
                )
            if item.requested_node_id:
                bind_metadata_alias(
                    by_node,
                    item.requested_node_id,
                    item,
                    kind="requested-node",
                )
            if item.node_id:
                bind_metadata_alias(
                    by_node,
                    item.node_id,
                    item,
                    kind="canonical-node",
                )
            if item.status in ("partial_error", "unverified_visibility"):
                unresolved += 1
                continue
            node_id = item.node_id or item.requested_node_id
            full_name = item.full_name or item.requested_full_name
            prior_repository = (
                state.get_repository(node_id) if node_id else None
            )
            try:
                prior_metadata = json.loads(
                    (prior_repository or {}).get("metadata_json") or "{}"
                )
            except (TypeError, ValueError):
                prior_metadata = {}
            resolved_metadata = _preserve_repository_lineage(
                item.to_dict(),
                prior_metadata,
            )
            metadata = {
                "node_id": node_id,
                "full_name": full_name,
                "visibility": item.visibility,
                "is_private": item.is_private,
                "is_fork": item.is_fork,
                "is_archived": item.is_archived,
                "default_branch": item.default_branch,
                "head_sha": item.head_oid,
                "metadata": resolved_metadata,
            }
            identity_names = tuple(
                name
                for name in (
                    item.full_name,
                    item.requested_full_name,
                )
                if isinstance(name, str) and name
            )
            globally_excluded = any(
                _repository_excluded(name) for name in identity_names
            )
            if globally_excluded:
                # A prior public row may already have candidates/results.  Feed
                # the exclusion through StateDB's fail-closed admission path so
                # the repository and all cascading state are purged rather than
                # merely hidden from this release.
                metadata["visibility"] = "excluded"
            if metadata["node_id"] or metadata["full_name"]:
                admitted = state.upsert_repository(metadata)
            else:
                admitted = None
            if (
                admitted
                and item.publishable
                and item.head_oid
                and item.full_name
                and not globally_excluded
            ):
                folded = item.full_name.casefold()
                prior = publishable_folded.get(folded)
                if (
                    prior is not None
                    and metadata_identity(prior) != metadata_identity(item)
                ):
                    raise PipelineError(
                        "GitHub metadata publishable-name collision for %s"
                        % item.full_name
                    )
                publishable_folded[folded] = item
                publishable[item.full_name] = item
        if unresolved:
            raise PipelineError("%d repository visibility states unresolved" % unresolved)
        return resolution, publishable, by_requested_name, by_node

    def _reattest_final_visibility(
        self,
        state: StateDB,
        run_id: str,
        current: Mapping[str, Any],
        initial_resolution: GraphQLResolution,
        budgets: RunBudgets,
        *,
        run_deadline: float | None,
        allow_resume: bool = False,
        final_visibility_privacy_control: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Freshly re-attest exactly the stable IDs about to become live."""
        if self.metadata is None:
            raise PipelineError("GitHub metadata adapter is not configured")
        node_ids, set_sha256 = _final_visibility_set(current)
        certified_missing_node_ids: tuple[str, ...] = ()
        attestation_node_ids = node_ids
        attestation_set_sha256 = set_sha256
        if final_visibility_privacy_control is not None:
            rejected_node = _phase8_final_visibility_rejected_node(
                state, run_id, final_visibility_privacy_control
            )
            if rejected_node in node_ids:
                raise PipelineError(
                    "certified final-visibility rejection was republished"
                )
            certified_missing_node_ids = (rejected_node,)
            attestation_node_ids = tuple(sorted((*node_ids, rejected_node)))
            attestation_set_sha256 = fingerprint(
                "final-visibility-set-v1", attestation_node_ids
            )
        batch_size = min(50, self._metadata_batch_size())
        batches = [
            attestation_node_ids[offset:offset + batch_size]
            for offset in range(0, len(attestation_node_ids), batch_size)
        ]
        epoch = None
        checked_at = None
        if allow_resume:
            prior_epochs: dict[str, dict[str, Any]] = {}
            for row in state.connection.execute(
                """
                SELECT task_id, task_key, payload_json
                FROM tasks
                WHERE run_id=?
                  AND stage='github-final-visibility-batch'
                ORDER BY task_id
                """,
                (run_id,),
            ):
                try:
                    payload = json.loads(row["payload_json"])
                except (TypeError, ValueError):
                    continue
                if not isinstance(payload, Mapping):
                    continue
                raw_epoch = payload.get("epoch")
                raw_checked_at = payload.get("checked_at")
                if (
                    isinstance(raw_epoch, str)
                    and raw_epoch
                    and isinstance(raw_checked_at, str)
                    and raw_checked_at
                ):
                    prior_epochs.setdefault(raw_epoch, {
                        "checked_at": raw_checked_at,
                        "set_sha256": payload.get("set_sha256"),
                        "task_keys": [],
                    })["task_keys"].append(row["task_key"])
            if prior_epochs:
                epoch, prior = next(reversed(prior_epochs.items()))
                checked_at = prior["checked_at"]
                if prior["set_sha256"] != attestation_set_sha256:
                    raise FinalVisibilityRefreshRequired(
                        "prior final visibility set changed; fresh initial "
                        "metadata is required"
                    )
                if _final_visibility_age_seconds({
                    "checked_at": checked_at,
                }) > FINAL_VISIBILITY_MAX_AGE_SECONDS:
                    raise FinalVisibilityRefreshRequired(
                        "prior final visibility epoch is stale; fresh "
                        "initial metadata is required"
                    )
        if epoch is None:
            epoch = uuid.uuid4().hex
            epoch_started = datetime.datetime.now(datetime.timezone.utc)
            checked_at = epoch_started.replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z")
        else:
            epoch_started = datetime.datetime.fromisoformat(
                checked_at.replace("Z", "+00:00")
            )
        task_ids = []
        task_keys = []
        for ordinal, batch in enumerate(batches):
            payload = {
                "version": 1,
                "set_sha256": attestation_set_sha256,
                "epoch": epoch,
                "checked_at": checked_at,
                "lookups": [
                    {"node_id": node_id, "full_name": None}
                    for node_id in batch
                ],
            }
            payload_fp = fingerprint(
                "github-final-visibility-task-v1", payload
            )
            task_key = "epoch:%s:batch:%06d:%s" % (
                epoch[:16],
                ordinal,
                payload_fp[:24],
            )
            task_keys.append(task_key)
            task_ids.append(
                state.enqueue_task(
                    run_id,
                    "github-final-visibility-batch",
                    task_key,
                    payload=payload,
                    max_attempts=3,
                )
            )
        if allow_resume and prior_epochs:
            prior_keys = set(prior["task_keys"])
            if prior_keys != set(task_keys):
                raise FinalVisibilityRefreshRequired(
                    "prior final visibility task plan changed; fresh "
                    "initial metadata is required"
                )
        state.supersede_tasks(
            run_id,
            "github-final-visibility-batch",
            keep_task_keys=task_keys,
            reason="final-visibility-fresh-epoch",
        )
        parts: list[GraphQLResolution] = []
        reused = 0
        worker = "coordinator:%s:final-visibility" % run_id
        for batch, task_id in zip(batches, task_ids):
            if (
                run_deadline is not None
                and self.clock() >= run_deadline
            ):
                raise BudgetExceeded(
                    "wall-time budget exhausted during final visibility"
                )
            document = _completed_task_document(state, task_id)
            if document is not None:
                part = _metadata_result_from_task_result(document)
                _assert_final_visibility_part(
                    part, batch,
                    certified_missing_node_ids=certified_missing_node_ids,
                )
                parts.append(part)
                reused += 1
                continue
            journal_budget = _graphql_journal_budget(state, run_id)
            prior_points = int(journal_budget["points_used"])
            prior_remaining = journal_budget["remaining"]
            prior_reset = journal_budget["reset_at"]
            if prior_points + 1 > budgets.max_graphql_points:
                raise BudgetExceeded(
                    "same-run GitHub GraphQL point budget would be "
                    "exceeded before final visibility"
                )
            if (
                prior_remaining is not None
                and int(prior_remaining) - 1
                < budgets.min_graphql_remaining
            ):
                raise BudgetExceeded(
                    "same-run GitHub GraphQL remaining-quota reserve "
                    "would be crossed before final visibility"
                )
            restore_budget = getattr(
                self.metadata, "restore_run_budget", None
            )
            if callable(restore_budget):
                restore_budget(
                    points_spent=prior_points,
                    remaining=prior_remaining,
                    reset_at=prior_reset,
                )
            leased = state.lease_task_by_id(
                task_id,
                worker=worker,
                lease_seconds=NETWORK_TASK_LEASE_SECONDS,
            )
            if leased is None:
                raise PipelineError(
                    "final GitHub visibility task is not leaseable"
                )
            lookups = [
                RepositoryLookup(node_id=node_id)
                for node_id in batch
            ]
            try:
                def run_final_visibility_task():
                    try:
                        try:
                            part = self.metadata.resolve(
                                lookups,
                                deadline_monotonic=run_deadline,
                            )
                        except TypeError as exc:
                            if "deadline_monotonic" not in str(exc):
                                raise
                            part = self.metadata.resolve(lookups)
                    except BaseException:
                        # The server may have spent quota before a transport or
                        # decoding failure became visible locally. Journal a
                        # sanitized maximum-cost failure so resume accounting
                        # remains conservative without retaining private data.
                        maximum_points = int(
                            getattr(self.metadata, "_max_points", 10)
                        )
                        part = GraphQLResolution(
                            repositories=tuple(
                                RepositoryMetadata(
                                    request_key=lookup.key,
                                    requested_node_id=lookup.node_id,
                                    requested_full_name=None,
                                    node_id=lookup.node_id,
                                    full_name=None,
                                    visibility=None,
                                    is_private=None,
                                    is_fork=None,
                                    is_archived=None,
                                    default_branch=None,
                                    head_oid=None,
                                    renamed=False,
                                    status="partial_error",
                                    errors=(
                                        "final visibility transport failure",
                                    ),
                                )
                                for lookup in lookups
                            ),
                            errors=(
                                GraphQLError(
                                    message=(
                                        "final visibility transport failure"
                                    ),
                                    request_key=None,
                                    error_type="transport",
                                ),
                            ),
                            request_count=1,
                            points_used=max(1, maximum_points),
                            remaining=max(
                                0,
                                int(
                                    prior_remaining
                                    if prior_remaining is not None
                                    else budgets.min_graphql_remaining
                                )
                                - max(1, maximum_points),
                            ),
                            reset_at=prior_reset,
                        )
                    return _metadata_result_to_task_result(part)

                document = _complete_journaled_network_task(
                    state,
                    self.state_path,
                    task_id,
                    worker,
                    run_final_visibility_task,
                )
            except BaseException:
                try:
                    state.fail_task(
                        task_id,
                        worker=worker,
                        error_code="github-final-visibility-failed",
                        retry=True,
                    )
                except RuntimeError:
                    pass
                raise
            part = _metadata_result_from_task_result(document)
            parts.append(part)
            cumulative_budget = _graphql_journal_budget(state, run_id)
            if int(
                cumulative_budget["points_used"]
            ) > budgets.max_graphql_points:
                raise BudgetExceeded(
                    "combined GitHub GraphQL point budget exceeded"
                )
            if (
                part.remaining < budgets.min_graphql_remaining
            ):
                raise BudgetExceeded(
                    "GitHub GraphQL remaining-quota reserve crossed "
                    "during final visibility"
                )
            _assert_final_visibility_part(
                part, batch,
                certified_missing_node_ids=certified_missing_node_ids,
            )
        certified_rejections = [
            repository
            for part in parts
            for repository in part.repositories
            if (
                repository.requested_node_id
                in set(certified_missing_node_ids)
                and repository.status == "missing"
            )
        ]
        if certified_missing_node_ids and len(certified_rejections) != 1:
            raise PipelineError(
                "certified final-visibility rejection coverage changed"
            )
        cumulative_budget = _graphql_journal_budget(state, run_id)
        epoch_completed = datetime.datetime.now(datetime.timezone.utc)
        completed_at = epoch_completed.replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z")
        oldest_age = max(
            0.0, (epoch_completed - epoch_started).total_seconds()
        )
        return {
            "version": 1,
            "set_sha256": set_sha256,
            "checked_at": checked_at,
            "epoch_completed_at": completed_at,
            "oldest_attestation_age_seconds": round(oldest_age, 3),
            "max_attestation_age_seconds": (
                FINAL_VISIBILITY_MAX_AGE_SECONDS
            ),
            "repository_count": len(node_ids),
            "batch_size": batch_size,
            "batch_count": len(batches),
            "graphql_requests": sum(
                part.request_count for part in parts
            ),
            "graphql_points": sum(part.points_used for part in parts),
            "graphql_remaining": (
                min(part.remaining for part in parts)
                if parts
                else int(initial_resolution.remaining)
            ),
            "graphql_reset_at": next(
                (
                    part.reset_at
                    for part in reversed(parts)
                    if part.reset_at is not None
                ),
                initial_resolution.reset_at,
            ),
            "run_graphql_requests": int(
                cumulative_budget["request_count"]
            ),
            "run_graphql_points": int(cumulative_budget["points_used"]),
            "run_graphql_remaining": (
                min(part.remaining for part in parts)
                if parts
                else int(initial_resolution.remaining)
            ),
            "tasks_total": len(task_ids),
            "tasks_completed": len(parts),
            "tasks_reused": reused,
            "queue_depth": state.connection.execute(
                """
                SELECT COUNT(*) FROM tasks
                WHERE run_id=? AND stage='github-final-visibility-batch'
                  AND status!='complete'
                """,
                (run_id,),
            ).fetchone()[0],
        }

    def _persist_candidates(
        self,
        state,
        run_id,
        observations,
        legacy,
        state_candidates,
        publishable,
        by_requested_name,
        by_node,
    ):
        libraries_by_id = {
            library["id"]: library for library in config.LIBRARIES
        }
        identity_metrics = {
            "observations_total": len(observations),
            "exact_node": 0,
            "name_fallback_after_node_miss": 0,
            "name_only": 0,
            "unresolved": 0,
            "not_publishable": 0,
            "evidence_excluded": 0,
        }
        blocked_pairs: set[tuple[str, str]] = set()

        def item_metadata(item):
            if item is None:
                return {}
            try:
                metadata = item.to_dict()
            except (AttributeError, TypeError):
                return {}
            if not isinstance(metadata, Mapping):
                return {}
            repository = (
                state.get_repository(item.node_id)
                if getattr(item, "node_id", None)
                else None
            )
            try:
                persisted = json.loads(
                    (repository or {}).get("metadata_json") or "{}"
                )
            except (TypeError, ValueError):
                persisted = {}
            return _preserve_repository_lineage(metadata, persisted)

        def retire(repository_id, library_id):
            if not repository_id:
                return
            repository = state.get_repository(repository_id)
            if repository is None or repository["visibility"] != "public":
                return
            state.retire_candidates(
                repository_id=repository_id,
                library_id=library_id,
                coverage_epoch=run_id,
            )

        def admitted_ids(
            name,
            library_ids,
            *,
            repository_id=None,
            repository_metadata=None,
        ):
            admitted = set()
            for library_id in library_ids:
                library = libraries_by_id.get(library_id)
                if library is None:
                    continue
                if (name.casefold(), library_id) in blocked_pairs:
                    retire(repository_id, library_id)
                    continue
                if _library_repository_excluded(
                    name,
                    library,
                    repository_metadata,
                ):
                    # Filtering is a durable policy verdict.  Previously active
                    # evidence must not survive into the public checkpoint.
                    retire(repository_id, library_id)
                    continue
                admitted.add(library_id)
            return admitted

        # GitHub's repository node-ID serialization has changed over time.
        # The metadata response is the authority for canonical identity; node
        # strings from discovery are aliases only when the same public result
        # also resolves the observation's requested/canonical full name.
        identity_items = tuple(
            {
                id(item): item
                for item in (
                    tuple(by_node.values())
                    + tuple(by_requested_name.values())
                    + tuple(publishable.values())
                )
                if item is not None
            }.values()
        )
        (
            resolved_by_name,
            resolved_by_node,
            publishable_by_name,
        ) = _canonical_metadata_identity_indexes(identity_items)
        excluded_observation_pairs = set()
        accepted_observation_pairs = set()
        for observation in observations:
            library = libraries_by_id.get(observation.library_id)
            item, _identity_kind = _resolve_canonical_observation_identity(
                observation,
                resolved_by_name=resolved_by_name,
                resolved_by_node=resolved_by_node,
            )
            if (
                library is None
                or item is None
                or not isinstance(item.full_name, str)
            ):
                continue
            pair = (item.full_name.casefold(), observation.library_id)
            if _discovery_observation_excluded(observation, library):
                excluded_observation_pairs.add(pair)
            else:
                accepted_observation_pairs.add(pair)
        blocked_pairs.update(
            excluded_observation_pairs - accepted_observation_pairs
        )

        grouped: dict[str, set[str]] = defaultdict(set)
        for old_name, ids in state_candidates.items():
            item = (
                by_requested_name.get(old_name.casefold())
                or resolved_by_name.get(old_name.casefold())
            )
            name = item.full_name if item and item.full_name else old_name
            if _repository_excluded(name):
                continue
            grouped[name].update(admitted_ids(
                name,
                ids,
                repository_id=(item.node_id if item else None),
                repository_metadata=item_metadata(item),
            ))
        for name, ids in legacy.items():
            item = (
                by_requested_name.get(name.casefold())
                or resolved_by_name.get(name.casefold())
            )
            current_name = item.full_name if item and item.full_name else name
            if _repository_excluded(current_name):
                continue
            grouped[current_name].update(admitted_ids(
                current_name,
                ids,
                repository_id=(item.node_id if item else None),
                repository_metadata=item_metadata(item),
            ))

        epoch = run_id
        for observation in observations:
            item, identity_kind = _resolve_canonical_observation_identity(
                observation,
                resolved_by_name=resolved_by_name,
                resolved_by_node=resolved_by_node,
            )
            identity_metrics[identity_kind] += 1
            canonical_publishable = (
                publishable_by_name.get(item.full_name.casefold())
                if item is not None
                and isinstance(getattr(item, "full_name", None), str)
                else None
            )
            if (
                item is None
                or not item.publishable
                or not item.full_name
                or canonical_publishable is None
                or _canonical_repository_identity(canonical_publishable)
                != _canonical_repository_identity(item)
                or _repository_excluded(item.full_name)
            ):
                if item is not None:
                    identity_metrics["not_publishable"] += 1
                continue
            library = libraries_by_id.get(observation.library_id)
            if (
                library is not None
                and _discovery_observation_excluded(
                    observation, library
                )
            ):
                identity_metrics["evidence_excluded"] += 1
                continue
            library_ids = admitted_ids(
                item.full_name,
                (observation.library_id,),
                repository_id=item.node_id,
                repository_metadata=item_metadata(item),
            )
            if not library_ids:
                continue
            grouped[item.full_name].update(library_ids)
            state.add_candidate(
                repository_id=item.node_id,
                library_id=observation.library_id,
                source=observation.source,
                query_fp=observation.query_fingerprint,
                coverage_epoch=epoch,
                signal=observation.signal_id,
                path=observation.matched_path or "",
                ref=observation.matched_blob or observation.matched_commit or "",
            )
        # The valid legacy release is durable recall input, but never a valid
        # current detector verdict.  Its candidates must be reconciled.
        for old_name, library_ids in legacy.items():
            item = (
                by_requested_name.get(old_name.casefold())
                or resolved_by_name.get(old_name.casefold())
            )
            if (
                item is None
                or not item.publishable
                or not item.node_id
                or not item.full_name
                or item.full_name not in publishable
                or _repository_excluded(item.full_name)
            ):
                continue
            retained_ids = admitted_ids(
                item.full_name,
                library_ids,
                repository_id=item.node_id,
                repository_metadata=item_metadata(item),
            )
            grouped[item.full_name].update(retained_ids)
            for library_id in retained_ids:
                state.add_candidate(
                    repository_id=item.node_id,
                    library_id=library_id,
                    source="legacy-release",
                    query_fp="last-good-v1",
                    coverage_epoch=epoch,
                signal="published-evidence",
            )
        self._candidate_identity_metrics = identity_metrics
        return {
            name: ids
            for name, ids in grouped.items()
            if name in publishable and ids
        }

    def _reusable(self, state, item, library_id, detector_fp):
        row = state.connection.execute(
            """
            SELECT status FROM scan_results
            WHERE repository_id=? AND library_id=? AND head_sha=?
              AND detector_fp=?
            """,
            (item.node_id, library_id, item.head_oid, detector_fp),
        ).fetchone()
        return bool(row and row["status"] == "clean")

    def _redate(self, state, run_id, dating_fp):
        """Journal and apply state-only dating derivations for positive rows."""
        rows = state.positive_scan_results_needing_redate(
            dating_fp=dating_fp
        )
        task_keys = {}
        for row in rows:
            task_keys[row["scan_result_id"]] = fingerprint(
                "redate-task-v1",
                {
                    "repository_id": row["repository_id"],
                    "library_id": row["library_id"],
                    "head_sha": row["head_sha"],
                    "detector_fp": row["detector_fp"],
                    "dating_fp": dating_fp,
                },
            )
        state.supersede_tasks(
            run_id,
            "redate",
            keep_task_keys=tuple(task_keys.values()),
            reason="replanned_immutable_work",
        )
        worker = "redate-coordinator:%s" % os.getpid()
        completed = 0
        for row in rows:
            task_id = state.enqueue_task(
                run_id,
                "redate",
                task_keys[row["scan_result_id"]],
                repository_id=row["repository_id"],
                library_id=row["library_id"],
                payload={
                    "head_sha": row["head_sha"],
                    "detector_fp": row["detector_fp"],
                    "dating_fp": dating_fp,
                },
            )
            leased = state.lease_task_by_id(
                task_id,
                worker=worker,
                lease_seconds=WORK_TASK_LEASE_SECONDS,
            )
            if leased is None:
                raise PipelineError(
                    "selected redating task could not be leased"
                )
            with state.transaction(immediate=True):
                state.redate_positive_scan_result(
                    row["scan_result_id"],
                    dating_fp=dating_fp,
                )
                state.complete_task(
                    task_id,
                    worker=worker,
                    result={
                        "status": "redated",
                        "scan_result_id": row["scan_result_id"],
                    },
                )
            completed += 1
        return completed

    def _scan(
        self,
        state,
        run_id,
        libraries,
        grouped,
        publishable,
        budgets,
        retirement_library_ids=(),
        run_deadline=None,
        retry_workers=None,
        defer_issue_lane=False,
        initial_workers=None,
        preserve_task_universe=False,
        allow_scan_bound_renames=False,
        fresh_candidate_deferral_control=None,
        post_refresh_privacy_control=None,
    ):
        by_library = {lib["id"]: lib for lib in libraries}
        # A run's immutable manifest is the authority for its evidence rows.
        # ``libraries`` is a shared catalog cache and can be refreshed while
        # an attended run is still active; reading fingerprints back from that
        # mutable table can therefore stamp a verdict with another run's
        # detector epoch.  Keep every reuse check, task key, and result write
        # bound to the plan that created this run.
        library_fingerprints = {
            library_id: _library_fp_values(
                self._active_plan, library_id
            )
            for library_id in self._active_plan.fingerprints.libraries
        }
        tasks = []
        eligible_pairs = 0
        reusable_pairs = 0
        eligible_repositories: set[str] = set()
        pairs_by_library: dict[str, dict[str, int]] = defaultdict(
            lambda: {"eligible": 0, "reused": 0, "dispatched": 0}
        )
        for name, library_ids in sorted(grouped.items()):
            item = publishable[name]
            missing = []
            for library_id in sorted(library_ids):
                if library_id not in by_library:
                    continue
                eligible_pairs += 1
                eligible_repositories.add(name)
                pairs_by_library[library_id]["eligible"] += 1
                if self._reusable(
                    state,
                    item,
                    library_id,
                    library_fingerprints[library_id]["detector"],
                ):
                    reusable_pairs += 1
                    pairs_by_library[library_id]["reused"] += 1
                else:
                    missing.append(library_id)
                    pairs_by_library[library_id]["dispatched"] += 1
            if missing:
                prior_boundaries = state.prior_first_use_boundaries(
                    repository_id=item.node_id,
                    current_head_sha=item.head_oid,
                    detector_fingerprints={
                        library_id: library_fingerprints[library_id][
                            "detector"
                        ]
                        for library_id in missing
                    },
                )
                tasks.append(ScanTask(
                    name,
                    item.head_oid,
                    tuple(missing),
                    estimated_size=(
                        None
                        if item.disk_usage_kb is None
                        else int(item.disk_usage_kb) * 1024
                    ),
                    prior_first_use_boundaries=tuple(
                        (
                            library_id,
                            json.dumps(
                                prior_boundaries[library_id],
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        )
                        for library_id in sorted(prior_boundaries)
                    ),
                ))
        task_names = {task.full_name for task in tasks}
        for name, item in sorted(publishable.items()):
            if name in task_names:
                continue
            positive_rows = state.connection.execute(
                """
                SELECT library_id, detector_fp FROM scan_results
                WHERE repository_id=? AND head_sha=?
                  AND status='clean' AND classification!='rejected'
                """,
                (item.node_id, item.head_oid),
            ).fetchall()
            has_positive = any(
                row["library_id"] in by_library
                and row["detector_fp"]
                == library_fingerprints[row["library_id"]]["detector"]
                for row in positive_rows
            )
            has_analysis = state.connection.execute(
                """
                SELECT 1 FROM repo_analysis
                WHERE repository_id=? AND head_sha=? AND ai_fp=?
                  AND status='clean' LIMIT 1
                """,
                (
                    item.node_id,
                    item.head_oid,
                    self._active_plan.fingerprints.ai,
                ),
            ).fetchone()
            if has_positive and has_analysis is None:
                tasks.append(
                    ScanTask(
                        name,
                        item.head_oid,
                        (),
                        estimated_size=(
                            None
                            if item.disk_usage_kb is None
                            else int(item.disk_usage_kb) * 1024
                        ),
                        analysis_only=True,
                    )
                )
        analysis_only_tasks = sum(bool(task.analysis_only) for task in tasks)
        scan_tasks = len(tasks) - analysis_only_tasks
        self._scan_selection_metrics = {
            "eligible_repository_count": len(eligible_repositories),
            "eligible_repository_library_pairs": eligible_pairs,
            "reusable_repository_library_pairs": reusable_pairs,
            "result_reuse_rate": round(
                reusable_pairs / eligible_pairs, 6
            ) if eligible_pairs else 1.0,
            "dispatched_repository_tasks": len(tasks),
            "dispatched_scan_tasks": scan_tasks,
            "analysis_only_tasks": analysis_only_tasks,
            "tasks_total": len(tasks),
            "tasks_completed": 0,
            "queue_depth": len(tasks),
            "by_library": {
                library_id: dict(values)
                for library_id, values in sorted(pairs_by_library.items())
            },
        }
        if len(tasks) > budgets.max_scan_repositories:
            raise BudgetExceeded(
                "scan plan exceeds repository budget (%d repositories)"
                % len(tasks)
            )
        library_fps = {
            library_id: values["detector"]
            for library_id, values in library_fingerprints.items()
        }
        task_keys = {
            task.full_name: fingerprint(
                "scan-task-v2",
                {
                    "repository_node_id": publishable[task.full_name].node_id,
                    "head_sha": task.head_sha,
                    "candidate_library_ids": sorted(
                        task.candidate_library_ids
                    ),
                    "analysis_only": task.analysis_only,
                    "ai_fingerprint": (
                        self._active_plan.fingerprints.ai
                        if task.analysis_only
                        else None
                    ),
                    "detector_fingerprints": {
                        library_id: library_fps.get(library_id)
                        for library_id in sorted(task.candidate_library_ids)
                    },
                },
            )
            for task in tasks
        }
        if preserve_task_universe:
            deferred_proof = (
                fresh_candidate_deferral_control.get("deferred_task_proof", [])
                if isinstance(fresh_candidate_deferral_control, Mapping)
                else []
            )
            deferred_by_key = {
                item["task_key"]: item for item in deferred_proof
            }
            promoted_nodes = set()
            if isinstance(post_refresh_privacy_control, Mapping):
                certified_epoch = post_refresh_privacy_control[
                    "fresh_metadata_epoch"
                ]
                certified_rows = list(state.connection.execute(
                    """
                    SELECT status,result_json FROM tasks
                    WHERE run_id=? AND stage='github-metadata-batch'
                      AND task_key LIKE ? ORDER BY task_id
                    """,
                    (run_id, "fresh:" + certified_epoch + ":%"),
                ))
                if (
                    len(certified_rows)
                    != post_refresh_privacy_control[
                        "fresh_metadata_batch_count"
                    ]
                    or any(
                        row["status"] != "complete"
                        for row in certified_rows
                    )
                ):
                    raise PipelineError(
                        "post-refresh promoted metadata epoch changed"
                    )
                for row in certified_rows:
                    try:
                        document = json.loads(row["result_json"] or "{}")
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise PipelineError(
                            "post-refresh promoted metadata is malformed"
                        ) from exc
                    for repository in document.get("repositories", []):
                        if (
                            repository.get("requested_node_id") is None
                            and repository.get("admitted_public") is True
                            and repository.get("node_id") is not None
                        ):
                            promoted_nodes.add(str(repository["node_id"]))
            observed_deferred = []
            post_refresh_deferred = []
            retained_tasks = []
            for task in tasks:
                expected_payload = {
                    "full_name": task.full_name,
                    "head_sha": task.head_sha,
                    "libraries": list(task.candidate_library_ids),
                }
                row = state.connection.execute(
                    """
                    SELECT repository_id, payload_json FROM tasks
                    WHERE run_id=? AND stage='scan' AND task_key=?
                    """,
                    (run_id, task_keys[task.full_name]),
                ).fetchone()
                try:
                    actual_payload = json.loads(
                        row["payload_json"] if row is not None else "{}"
                    )
                except (TypeError, json.JSONDecodeError):
                    actual_payload = {}
                task_key = task_keys[task.full_name]
                if row is None and task_key in deferred_by_key:
                    item = publishable[task.full_name]
                    proof = {
                        "task_key": task_key,
                        "repository_identity_sha256": hashlib.sha256(
                            (item.node_id + "\0" + task.full_name).encode(
                                "utf-8"
                            )
                        ).hexdigest(),
                        "libraries": list(task.candidate_library_ids),
                    }
                    if proof != deferred_by_key[task_key]:
                        raise PipelineError(
                            "Phase 8 fresh-candidate deferral proof changed"
                        )
                    observed_deferred.append(proof)
                    continue
                item = publishable[task.full_name]
                if (
                    row is None
                    and item.node_id in promoted_nodes
                    and not task.analysis_only
                ):
                    has_prior_evidence = state.connection.execute(
                        """
                        SELECT 1 FROM scan_results WHERE repository_id=?
                        UNION ALL
                        SELECT 1 FROM repo_analysis WHERE repository_id=?
                        LIMIT 1
                        """,
                        (item.node_id, item.node_id),
                    ).fetchone()
                    if has_prior_evidence is None:
                        post_refresh_deferred.append({
                            "task_key": task_key,
                            "repository_identity_sha256": hashlib.sha256(
                                (item.node_id + "\0" + task.full_name).encode(
                                    "utf-8"
                                )
                            ).hexdigest(),
                            "libraries": list(task.candidate_library_ids),
                        })
                        continue
                if (
                    row is None
                    or task_key in deferred_by_key
                    or row["repository_id"]
                    != publishable[task.full_name].node_id
                    or actual_payload.get("head_sha") != task.head_sha
                    or actual_payload.get("libraries")
                    != list(task.candidate_library_ids)
                    or (
                        not allow_scan_bound_renames
                        and actual_payload.get("full_name")
                        != task.full_name
                    )
                ):
                    raise PipelineError(
                        "incident scan task is outside the immutable universe"
                    )
                retained_tasks.append(task)
            observed_deferred.sort(key=lambda item: item["task_key"])
            if observed_deferred != deferred_proof:
                raise PipelineError(
                    "Phase 8 fresh-candidate deferred task set changed"
                )
            post_refresh_deferred.sort(key=lambda item: item["task_key"])
            expected_post_refresh_deferred = int(
                isinstance(post_refresh_privacy_control, Mapping)
            )
            if len(post_refresh_deferred) != expected_post_refresh_deferred:
                raise PipelineError(
                    "Phase 8 post-refresh deferred task set changed"
                )
            tasks = retained_tasks
            # The reviewed proof currently permits detector work only.  Keep
            # the metric derivation explicit so analysis-only additions remain
            # a closed failure rather than silently joining the deferral.
            deferred_scan_count = (
                len(observed_deferred) + len(post_refresh_deferred)
            )
            self._scan_selection_metrics.update({
                "fresh_candidate_deferred_tasks": deferred_scan_count,
                "post_refresh_deferred_tasks": len(
                    post_refresh_deferred
                ),
                "post_refresh_deferred_task_proof_sha256": (
                    _canonical_sha256(post_refresh_deferred)
                    if post_refresh_deferred
                    else None
                ),
                "dispatched_repository_tasks": len(tasks),
                "dispatched_scan_tasks": max(0, scan_tasks - deferred_scan_count),
                "tasks_total": len(tasks),
                "queue_depth": len(tasks),
            })
        else:
            state.supersede_tasks(
                run_id,
                "scan",
                keep_task_keys=tuple(task_keys.values()),
                reason="replanned_immutable_work",
            )
        dispatchable_tasks = []
        blocked_failures = []
        for task in tasks:
            row = state.connection.execute(
                """
                SELECT status,error_code
                FROM tasks
                WHERE run_id=? AND stage='scan' AND task_key=?
                """,
                (run_id, task_keys[task.full_name]),
            ).fetchone()
            if row is None or row["status"] == "pending":
                dispatchable_tasks.append(task)
                continue
            if row["status"] == "failed":
                blocked_failures.append({
                    "full_name": task.full_name,
                    "error_code": (
                        row["error_code"] or "scan_task_failed"
                    ),
                    "retryable": False,
                    "task_status": "failed",
                })
                continue
            raise PipelineError(
                "selected scan task has an invalid durable dispatch state"
            )
        self._scan_selection_metrics.update({
            "dispatchable_tasks": len(dispatchable_tasks),
            "blocked_terminal_tasks": len(blocked_failures),
            "queue_depth": len(dispatchable_tasks) + len(blocked_failures),
        })
        tasks = dispatchable_tasks
        prior_attempt_usage = _scan_attempt_usage_for_run(
            state, run_id
        )
        _enforce_scan_attempt_budgets(
            prior_attempt_usage,
            planned_attempts=len(tasks),
            budgets=budgets,
        )
        prior_attempt_count = int(
            prior_attempt_usage["attempt_count"]
        )
        prior_materialized_bytes = int(
            prior_attempt_usage["network_materialized_bytes"]
        )
        historical_attempts = int(
            prior_attempt_usage["historical"]["attempt_count"]
        )
        current_attempts = int(
            prior_attempt_usage["current"]["attempt_count"]
        )
        historical_materialized_bytes = int(
            prior_attempt_usage["historical"]["usage"][
                "network_materialized_bytes"
            ]
        )
        current_materialized_bytes = int(
            prior_attempt_usage["current"][
                "network_materialized_bytes"
            ]
        )
        self._scan_attempt_usage = dict(prior_attempt_usage)
        self._scan_selection_metrics.update({
            "historical_scan_attempts": historical_attempts,
            "current_scan_attempts": current_attempts,
            "prior_scan_attempts": prior_attempt_count,
            "planned_scan_attempts": (
                prior_attempt_count + len(tasks)
            ),
            "historical_git_materialized_bytes": (
                historical_materialized_bytes
            ),
            "current_git_materialized_bytes": (
                current_materialized_bytes
            ),
            "prior_git_materialized_bytes": (
                prior_materialized_bytes
            ),
        })
        if not tasks:
            self._scan_selection_metrics["attempt_usage"] = dict(
                self._scan_attempt_usage
            )
            if blocked_failures:
                self._scan_selection_metrics["failures"] = list(
                    blocked_failures
                )
                raise PipelineError(
                    "%d selected scans unresolved; last-good release preserved"
                    % len(blocked_failures)
                )
            self._scan_selection_metrics["queue_depth"] = 0
            for name, library_ids in sorted(grouped.items()):
                item = publishable[name]
                for library_id in sorted(
                    set(library_ids) & set(retirement_library_ids)
                ):
                    row = state.connection.execute(
                        """
                        SELECT classification FROM scan_results
                        WHERE repository_id=? AND library_id=? AND head_sha=?
                          AND detector_fp=? AND status='clean'
                        """,
                        (
                            item.node_id,
                            library_id,
                            item.head_oid,
                            library_fps.get(library_id),
                        ),
                    ).fetchone()
                    if row is not None and row["classification"] == "rejected":
                        state.retire_candidates(
                            repository_id=item.node_id,
                            library_id=library_id,
                            coverage_epoch=run_id,
                        )
            return [], 0

        task_ids = {}
        worker = "coordinator:%s" % os.getpid()
        # Active tasks renew once per minute. A killed coordinator therefore
        # makes at most the worker-slot-sized active set retryable within ten
        # minutes, regardless of a 36-hour reconciliation budget.
        lease = float(WORK_TASK_LEASE_SECONDS)
        for task in tasks:
            task_ids[task.full_name] = state.enqueue_task(
                run_id,
                "scan",
                task_keys[task.full_name],
                repository_id=publishable[task.full_name].node_id,
                payload={
                    "full_name": task.full_name,
                    "head_sha": task.head_sha,
                    "libraries": list(task.candidate_library_ids),
                },
                max_attempts=2,
            )
        leased = {}
        expected = {task.full_name.casefold(): task for task in tasks}

        def lease_for_dispatch(task):
            key = task.full_name.casefold()
            expected_task = expected.get(key)
            if expected_task != task:
                raise PipelineError(
                    "scanner attempted to dispatch an unselected task"
                )
            if key in leased:
                return leased[key]
            row = state.lease_task_by_id(
                task_ids[task.full_name],
                worker=worker,
                lease_seconds=lease,
            )
            if row is None:
                raise PipelineError(
                    "selected scan task could not be leased for dispatch"
                )
            leased[key] = row["task_id"]
            return row["task_id"]

        failures = list(blocked_failures)
        retryable_names: set[str] = set()
        checkpointed: set[str] = set()
        materialized_bytes = prior_materialized_bytes
        budget_failure: str | None = None

        def renew_active_tasks():
            for key, task_id in tuple(leased.items()):
                if key in checkpointed:
                    continue
                if not state.renew_task(
                    task_id,
                    worker=worker,
                    lease_seconds=lease,
                ):
                    raise PipelineError(
                        "selected scan task lease was lost"
                    )

        def scan_attempt_document(
            outcome,
            *,
            error_code: str | None = None,
            retryable: bool = False,
            error: str | None = None,
        ):
            document = {
                "version": 1,
                "kind": (
                    "scan-failure"
                    if error_code is not None
                    else "scan-attempt"
                ),
                "status": (
                    "error"
                    if error_code is not None
                    else outcome.status
                ),
                "head_sha": outcome.head_sha,
                "seconds": round(outcome.seconds, 3),
                "current_tree_triage_seconds": round(
                    outcome.current_tree_triage_seconds, 3
                ),
                "history_dating_seconds": round(
                    outcome.history_dating_seconds, 3
                ),
                "analysis_seconds": round(
                    outcome.analysis_seconds, 3
                ),
                "git_subprocess_count": outcome.git_subprocess_count,
                "network_clone_count": outcome.network_clone_count,
                "network_fetch_count": outcome.network_fetch_count,
                "network_materialized_bytes": (
                    outcome.network_materialized_bytes
                ),
            }
            if error_code is not None:
                document.update({
                    "error_code": error_code,
                    "retryable": bool(retryable),
                    "error": str(
                        error or "repository scan failed"
                    )[:500],
                })
            else:
                document.update({
                    "cache_hit": outcome.cache_hit,
                    "cache_bytes": outcome.cache_bytes,
                })
            return document

        def checkpoint(outcome):
            nonlocal budget_failure, materialized_bytes
            if budget_failure is not None:
                raise BudgetExceeded(budget_failure)
            full_name = getattr(outcome, "full_name", None)
            key = full_name.casefold() if isinstance(full_name, str) else ""
            task = expected.get(key)
            if task is None:
                raise PipelineError(
                    "scanner returned an outcome for an unselected repository"
                )
            if (
                full_name != task.full_name
                or outcome.head_sha != task.head_sha
                or tuple(outcome.candidate_library_ids)
                != tuple(task.candidate_library_ids)
            ):
                raise PipelineError(
                    "scanner outcome identity does not match its selected task"
                )
            if key in checkpointed:
                raise PipelineError(
                    "scanner checkpointed a selected task more than once"
                )
            next_materialized_bytes = (
                materialized_bytes
                + int(outcome.network_materialized_bytes)
            )
            if next_materialized_bytes > budgets.max_git_materialized_bytes:
                error_code = "git_materialization_budget_exceeded"
                error = (
                    "Git materialization byte budget exhausted "
                    "during scan (%d > %d)"
                    % (
                        next_materialized_bytes,
                        budgets.max_git_materialized_bytes,
                    )
                )
                # The worker completed this dispatch and supplied exact usage.
                # Close the durable attempt before surfacing the run-level
                # budget error; otherwise a resume would see an unknowable
                # running attempt and could neither charge nor retry safely.
                task_id = lease_for_dispatch(task)
                attempt_document = scan_attempt_document(
                    outcome,
                    error_code=error_code,
                    retryable=False,
                    error=error,
                )
                state.record_scan_attempt_result(
                    task_id,
                    worker=worker,
                    status="failed",
                    retryable=False,
                    error_code=error_code,
                    result=attempt_document,
                )
                with state.transaction(immediate=True):
                    state.fail_task(
                        task_id,
                        worker=worker,
                        error_code=error_code,
                        result=attempt_document,
                        retry=False,
                    )
                checkpointed.add(key)
                budget_failure = error
                raise BudgetExceeded(
                    error
                )
            materialized_bytes = next_materialized_bytes
            task_id = lease_for_dispatch(task)
            error_code = None
            retryable = False
            error = None
            if outcome.status == "error" or outcome.result is None:
                error_code = (
                    outcome.error_code
                    if isinstance(outcome.error_code, str)
                    and outcome.error_code
                    else "detector_error"
                )
                retryable = bool(outcome.error_retryable)
                error = str(
                    outcome.error or "repository scan failed"
                )[:500]
                if defer_issue_lane:
                    error_code, retryable, error = (
                        _phase8_runtime_issue_contract(
                            error_code, retryable, error
                        )
                    )
            attempt_document = scan_attempt_document(
                outcome,
                error_code=error_code,
                retryable=retryable,
                error=error,
            )
            state.record_scan_attempt_result(
                task_id,
                worker=worker,
                status=(
                    "failed"
                    if error_code is not None
                    else "complete"
                ),
                retryable=retryable,
                error_code=error_code,
                result=attempt_document,
            )
            checkpointed.add(key)
            # The result rows, repository-wide analysis, cross-library
            # candidates, and journal completion are one crash boundary. The
            # attempt's exact resource charge is durably recorded first, so a
            # coordinator death can retry a missing verdict without losing or
            # double-counting completed network work.
            with state.transaction(immediate=True):
                item = publishable[outcome.full_name]
                if error_code is not None:
                    task_status = state.fail_task(
                        task_id,
                        worker=worker,
                        error_code=error_code,
                        result=attempt_document,
                        retry=retryable,
                    )
                    failures.append({
                        "full_name": outcome.full_name,
                        "error_code": error_code,
                        "retryable": retryable,
                        "task_status": task_status,
                    })
                    if retryable and task_status == "pending":
                        retryable_names.add(key)
                    return
                result_rows = (outcome.result or {}).get("libraries", {})
                evaluated = (
                    set(outcome.candidate_library_ids)
                    | set(outcome.triaged_library_ids)
                    | set(result_rows)
                )
                for library_id in sorted(evaluated):
                    if library_id not in library_fps:
                        continue
                    evidence = result_rows.get(library_id)
                    state.record_scan_result(
                        repository_id=item.node_id,
                        library_id=library_id,
                        head_sha=outcome.head_sha,
                        detector_fp=library_fps[library_id],
                        classification=(
                            evidence["classification"] if evidence else "rejected"
                        ),
                        status="clean",
                        evidence=(
                            {
                                **(evidence or {}),
                                "_dating_fp": (
                                    library_fingerprints[library_id]["dating"]
                                ),
                            }
                            if evidence
                            else {}
                        ),
                        raw_first_commit=(
                            (
                                (
                                    evidence.get(
                                        "_first_use_boundaries"
                                    ) or {}
                                ).get("primary") or {}
                            ).get("commit")
                            or evidence.get("first_integration_commit")
                            if evidence else None
                        ),
                        raw_first_date=(
                            evidence.get("first_integration") if evidence else None
                        ),
                        derived_first_date=(
                            evidence.get("first_integration") if evidence else None
                        ),
                    )
                    if library_id in outcome.triaged_library_ids:
                        state.add_candidate(
                            repository_id=item.node_id,
                            library_id=library_id,
                            source="cross-library-scan",
                            query_fp="one-pass-v2",
                            coverage_epoch=run_id,
                            signal="current-tree-anchor",
                        )
                if outcome.result:
                    analysis = {
                        key: outcome.result.get(key)
                        for key in (
                            "total_commits", "ai_agents", "ai_config_files",
                            "citation_cff_files", "citation_cff", "triage",
                        )
                    }
                    state.record_repo_analysis(
                        repository_id=item.node_id,
                        head_sha=outcome.head_sha,
                        ai_fp=self._active_plan.fingerprints.ai,
                        cff_fp=fingerprint(
                            "repository:cff",
                            analysis.get("citation_cff") or {},
                        ),
                        analysis=analysis,
                        status="clean",
                    )
                for library_id in sorted(evaluated):
                    if (
                        library_id in retirement_library_ids
                        and library_id not in result_rows
                    ):
                        state.retire_candidates(
                            repository_id=item.node_id,
                            library_id=library_id,
                            coverage_epoch=run_id,
                        )
                state.complete_task(
                    task_id,
                    worker=worker,
                    result=attempt_document,
                )

        outcome_by_name = {}

        initial_workers = (
            budgets.workers
            if initial_workers is None
            else int(initial_workers)
        )
        if not 1 <= initial_workers <= budgets.workers:
            raise PipelineError("scan initial worker count is invalid")
        retry_workers = (
            budgets.workers
            if retry_workers is None
            else int(retry_workers)
        )
        if not 1 <= retry_workers <= budgets.workers:
            raise PipelineError("scan retry worker count is invalid")

        def run_scan_batch(batch, *, workers=None):
            if not batch:
                return
            selected_workers = (
                initial_workers if workers is None else int(workers)
            )
            if not 1 <= selected_workers <= budgets.workers:
                raise PipelineError("scan batch worker count is invalid")
            batch_outcomes = list(
                self.scan_runner(
                    batch,
                    libraries,
                    self.cache_root,
                    workers=selected_workers,
                    repo_timeout=budgets.repo_timeout_seconds,
                    cache_target_bytes=budgets.cache_target_bytes,
                    cache_hard_bytes=budgets.cache_hard_bytes,
                    on_result=checkpoint,
                    before_task=lease_for_dispatch,
                    on_heartbeat=renew_active_tasks,
                    run_deadline=run_deadline,
                )
            )
            batch_expected = {
                task.full_name.casefold(): task for task in batch
            }
            batch_returned = set()
            for outcome in batch_outcomes:
                full_name = getattr(outcome, "full_name", None)
                key = (
                    full_name.casefold()
                    if isinstance(full_name, str)
                    else ""
                )
                task = batch_expected.get(key)
                if key in batch_returned:
                    raise PipelineError(
                        "scanner returned a selected task more than once"
                    )
                if (
                    task is None
                    or full_name != task.full_name
                    or outcome.head_sha != task.head_sha
                    or tuple(outcome.candidate_library_ids)
                    != tuple(task.candidate_library_ids)
                ):
                    raise PipelineError(
                        "scanner batch returned an invalid task outcome"
                    )
                batch_returned.add(key)
                outcome_by_name[key] = outcome
            if batch_returned != set(batch_expected):
                raise PipelineError(
                    "scanner outcomes do not exactly cover selected tasks"
                )

        historical_contract = _historical_scan_usage_for_run(
            state, run_id
        )
        priority_names = {
            str(row["full_name"]).casefold()
            for row in (
                historical_contract.get("proof_rows", ())
                if historical_contract is not None
                else ()
            )
            if (
                row.get("run_id")
                == (
                    historical_contract.get("predecessor_run_id")
                    if historical_contract is not None
                    else None
                )
                and (row.get("evidence") or {}).get("attempt_status")
                in {"failed", "interrupted"}
            )
        }
        priority_tasks = [
            task for task in tasks
            if task.full_name.casefold() in priority_names
        ]
        remaining_tasks = [
            task for task in tasks
            if task.full_name.casefold() not in priority_names
        ]

        if defer_issue_lane:
            attempted_names = {
                task.full_name.casefold()
                for task in tasks
                if int(
                    state.connection.execute(
                        "SELECT attempts FROM tasks WHERE task_id=?",
                        (task_ids[task.full_name],),
                    ).fetchone()[0]
                )
                > 0
            }
            issue_tasks = [
                task for task in tasks
                if task.full_name.casefold() in attempted_names
            ]
            remaining_tasks = [
                task for task in tasks
                if task.full_name.casefold() not in attempted_names
            ]
            priority_tasks = []
        else:
            issue_tasks = []

        def retry_pending(batch):
            names = {
                task.full_name.casefold() for task in batch
            } & retryable_names
            if not names:
                return
            retry_tasks = [
                expected[name] for name in sorted(names)
            ]
            usage = _scan_attempt_usage_for_run(state, run_id)
            _enforce_scan_attempt_budgets(
                usage,
                planned_attempts=len(retry_tasks),
                budgets=budgets,
            )
            for name in names:
                leased.pop(name, None)
                checkpointed.discard(name)
                retryable_names.discard(name)
            failures[:] = [
                failure for failure in failures
                if failure["full_name"].casefold() not in names
            ]
            run_scan_batch(retry_tasks, workers=retry_workers)

        run_scan_batch(priority_tasks)
        retry_pending(priority_tasks)
        run_scan_batch(remaining_tasks)
        retry_pending(remaining_tasks)
        run_scan_batch(issue_tasks, workers=retry_workers)
        retry_pending(issue_tasks)
        outcomes = sorted(
            outcome_by_name.values(),
            key=lambda outcome: outcome.full_name.casefold(),
        )
        if budget_failure is not None:
            self._scan_attempt_usage = _scan_attempt_usage_for_run(
                state, run_id
            )
            self._scan_selection_metrics[
                "attempt_usage"
            ] = dict(self._scan_attempt_usage)
            raise BudgetExceeded(budget_failure)
        returned: set[str] = set()
        for outcome in outcomes:
            full_name = getattr(outcome, "full_name", None)
            key = full_name.casefold() if isinstance(full_name, str) else ""
            task = expected.get(key)
            if task is None:
                raise PipelineError(
                    "scanner returned an outcome for an unselected repository"
                )
            if (
                full_name != task.full_name
                or outcome.head_sha != task.head_sha
                or tuple(outcome.candidate_library_ids)
                != tuple(task.candidate_library_ids)
            ):
                raise PipelineError(
                    "scanner outcome identity does not match its selected task"
                )
            if key in returned:
                raise PipelineError(
                    "scanner returned a selected task more than once"
                )
            returned.add(key)
        expected_keys = set(expected)
        if returned != expected_keys or checkpointed != expected_keys:
            raise PipelineError(
                "scanner outcomes/checkpoints do not exactly cover selected tasks"
            )
        if failures:
            self._scan_attempt_usage = _scan_attempt_usage_for_run(
                state, run_id
            )
            self._scan_selection_metrics[
                "attempt_usage"
            ] = dict(self._scan_attempt_usage)
            self._scan_selection_metrics["failures"] = failures
            raise PipelineError(
                "%d selected scans unresolved; last-good release preserved"
                % len(failures)
            )
        self._scan_selection_metrics["tasks_completed"] = len(outcomes)
        self._scan_attempt_usage = _scan_attempt_usage_for_run(
            state, run_id
        )
        self._scan_selection_metrics["attempt_usage"] = dict(
            self._scan_attempt_usage
        )
        self._scan_selection_metrics["queue_depth"] = int(
            state.connection.execute(
                """
                SELECT COUNT(*) FROM tasks
                WHERE run_id=? AND stage='scan' AND status!='complete'
                """,
                (run_id,),
            ).fetchone()[0]
        )
        # A prior clean reject may be reusable at the same HEAD.  Once the
        # fresh two-source epoch is complete it can retire without another
        # checkout; any later observation reactivates the candidate.
        for name, library_ids in sorted(grouped.items()):
            item = publishable[name]
            for library_id in sorted(
                set(library_ids) & set(retirement_library_ids)
            ):
                detector_fp = library_fps.get(library_id)
                row = state.connection.execute(
                    """
                    SELECT classification FROM scan_results
                    WHERE repository_id=? AND library_id=? AND head_sha=?
                      AND detector_fp=? AND status='clean'
                    """,
                    (
                        item.node_id,
                        library_id,
                        item.head_oid,
                        detector_fp,
                    ),
                ).fetchone()
                if row is not None and row["classification"] == "rejected":
                    state.retire_candidates(
                        repository_id=item.node_id,
                        library_id=library_id,
                        coverage_epoch=run_id,
                    )
        return outcomes, len(tasks)

    def _materialize(
        self,
        state,
        libraries,
        discovery_metrics,
        *,
        mode,
        selected_library_ids,
        scan_quality,
        cohort_contract=None,
    ):
        cohort = cohort_contract is not None
        selected_library_ids = set(selected_library_ids)
        rows = state.connection.execute(
            """
            SELECT r.*, s.library_id, s.classification, s.evidence_json,
                   a.analysis_json
            FROM repositories r
            JOIN scan_results s
              ON s.repository_id=r.node_id AND s.head_sha=r.head_sha
            JOIN libraries l
              ON l.library_id=s.library_id AND l.detector_fp=s.detector_fp
            LEFT JOIN repo_analysis a
              ON a.repository_id=r.node_id AND a.head_sha=r.head_sha
             AND a.ai_fp=?
            WHERE r.visibility='public' AND r.is_fork=0 AND r.is_archived=0
              AND s.status='clean' AND s.classification!='rejected'
            ORDER BY r.full_name, s.library_id
            """,
            (self._active_plan.fingerprints.ai,),
        ).fetchall()
        grouped = defaultdict(lambda: {"libraries": [], "analysis": {}})
        metadata = {}
        libs_by_id = {lib["id"]: lib for lib in libraries}
        for row in rows:
            if (
                cohort
                and row["library_id"] not in selected_library_ids
            ):
                continue
            library = libs_by_id.get(row["library_id"])
            try:
                repository_metadata = json.loads(
                    row["metadata_json"] or "{}"
                )
            except (TypeError, ValueError):
                repository_metadata = {}
            if (
                library is None
                or _repository_excluded(row["full_name"])
                or _library_repository_excluded(
                    row["full_name"],
                    library,
                    repository_metadata,
                )
            ):
                if _repository_excluded(row["full_name"]):
                    state.upsert_repository({
                        "node_id": row["node_id"],
                        "full_name": row["full_name"],
                        "visibility": "excluded",
                    })
                elif library is not None:
                    filter_epoch = "filter-policy:" + (
                        self._active_plan.fingerprints.filters.get(
                            "nvpl"
                            if (
                                library.get("id") == "nvpl"
                                or library.get("family") == "nvpl"
                            )
                            else "shared",
                            "current",
                        )
                    )
                    state.retire_candidates(
                        repository_id=row["node_id"],
                        library_id=row["library_id"],
                        coverage_epoch=filter_epoch,
                    )
                continue
            raw_evidence = json.loads(row["evidence_json"])
            if row["library_id"] == "nvpl":
                components = reviewed_components(
                    row["full_name"], row["head_sha"], raw_evidence
                )
                if components:
                    raw_evidence["operators"] = sorted(
                        set(raw_evidence.get("operators") or ())
                        | set(components)
                    )
            evidence = {
                key: value
                for key, value in raw_evidence.items()
                if not str(key).startswith("_")
            }
            grouped[row["full_name"]]["libraries"].append(
                dict(library_id=row["library_id"], **evidence)
            )
            if row["analysis_json"]:
                grouped[row["full_name"]]["analysis"] = json.loads(row["analysis_json"])
            metadata[row["full_name"]] = dict(row)

        repos = []
        for name, value in grouped.items():
            analysis = value["analysis"]
            sc = {
                "libraries": {
                    entry["library_id"]: {
                        key: item for key, item in entry.items()
                        if key != "library_id"
                    }
                    for entry in value["libraries"]
                },
                "total_commits": analysis.get("total_commits", 0) or 0,
                "ai_agents": analysis.get("ai_agents", {}) or {},
                "ai_config_files": analysis.get("ai_config_files", []) or [],
            }
            raw_meta = json.loads(metadata[name]["metadata_json"] or "{}")
            m = {
                "html_url": "https://github.com/" + name,
                "owner": name.split("/", 1)[0],
                "description": None,
                "stars": 0,
                "forks": 0,
                "language": None,
                "archived": False,
                "created_at": None,
                "pushed_at": None,
                **(raw_meta.get("display") or {}),
            }
            entry = run._build_entry(name, sc, m, list(libs_by_id.values()))
            if entry:
                entry["visibility"] = "PUBLIC"
                entry["repository_node_id"] = metadata[name]["node_id"]
                entry["head_sha"] = metadata[name]["head_sha"]
                repos.append(entry)

        carried_library_ids: set[str] = set()
        legacy_current: dict[str, Any] = {}
        if mode == "onboard" or cohort:
            public_name_map: dict[str, str] = {}
            public_metadata_map: dict[str, Mapping[str, Any]] = {}
            for row in state.connection.execute(
                """
                SELECT node_id, full_name, metadata_json FROM repositories
                WHERE visibility='public' AND is_fork=0 AND is_archived=0
                """
            ):
                current_name = row["full_name"]
                public_name_map[current_name.casefold()] = current_name
                try:
                    current_metadata = json.loads(
                        row["metadata_json"] or "{}"
                    )
                except (TypeError, ValueError):
                    current_metadata = {}
                current_metadata = {
                    **current_metadata,
                    "node_id": row["node_id"],
                }
                public_metadata_map[current_name.casefold()] = current_metadata
                requested = current_metadata.get("requested_full_name")
                if isinstance(requested, str) and requested:
                    public_name_map[requested.casefold()] = current_name
            repos, carried_library_ids, legacy_current = (
                _carry_forward_unselected_v1(
                    repos,
                    self.data_dir,
                    set(selected_library_ids),
                    public_name_map,
                    public_metadata_map,
                    include_previously_measured=cohort,
                )
            )
        # Components are independent products.  Remove any explicit legacy
        # component-to-parent materialization carried from an older checkpoint;
        # only NVPL has an additive parent contract, applied after aggregation.
        _restore_direct_parent_entries(repos)
        repos, mirror_drops = run._dedup_mirrors(repos, lambda _message: None)
        if (mode == "onboard" or cohort) and "nvpl" in selected_library_ids:
            # Mirror identity is determined only from current scan evidence.
            # V1 subtype preservation is presentation-only and must not turn
            # an otherwise identical historical mirror into a second adopter.
            _preserve_nvpl_component_memberships(
                repos, legacy_current, public_name_map
            )
        discovery_stats = _discovery_stats(libraries, discovery_metrics)
        legacy_stats = legacy_current.get("discovery_stats") or {}
        legacy_as_of = legacy_current.get("generated_at")
        for library_id in carried_library_ids:
            raw = legacy_stats.get(library_id)
            value = dict(raw) if isinstance(raw, Mapping) else {}
            value.update({
                "evidence_kind": "carried-forward-v1",
                "stale": True,
                "carried_forward": True,
                "as_of": legacy_as_of,
            })
            value.setdefault("coverage_gaps", [])
            value.setdefault("sources", {})
            value.setdefault("source_lag_max_seconds", None)
            value.pop("certificates", None)
            discovery_stats[library_id] = value
        today = datetime.date.today()
        current, timeseries = run.aggregate(
            repos,
            libraries,
            today,
            discovery_stats,
            {},
            mirror_drops,
        )
        projected_component_ids = {
            card["id"]
            for card in current.get("libraries", ())
            if card.get("is_component")
            and card.get("parent_id") in selected_library_ids
            and card.get("component_label")
        }
        # These cards were freshly re-projected from selected parent evidence;
        # they are not stale carried V1 products.
        carried_library_ids.difference_update(projected_component_ids)
        if cohort:
            # Historical V1 rows remain available to audits and exports but
            # never turn a deferred product into a measured zero or a current
            # family rollup.
            not_evaluated = {
                classification: "not_evaluated"
                for classification in ("confirmed", "bundled", "targeted")
            }
            for card in current.get("libraries", ()):
                if card.get("id") not in carried_library_ids:
                    continue
                card["collection_status"] = "not_collected"
                card["classification_coverage"] = dict(not_evaluated)
                card["not_evaluated_classes"] = sorted(not_evaluated)
                for field in (
                    "confirmed_count",
                    "bundled_count",
                    "targeted_count",
                    "headline_count",
                ):
                    card[field] = None
        from .portfolio import build_portfolio
        evidence_library_ids = {
            entry["library_id"]
            for repo in current["repos"]
            for entry in repo.get("libraries", ())
            if isinstance(entry, Mapping)
            and isinstance(entry.get("library_id"), str)
        }
        prior_v2 = _load_json(self.data_dir / "v2" / "manifest.json", {})
        previously_measured_ids = {
            card["id"]
            for card in prior_v2.get("libraries", ())
            if isinstance(card, Mapping)
            and isinstance(card.get("id"), str)
            and card.get("collection_status") == "collected"
        }
        measured_library_ids = (
            set(selected_library_ids)
            | evidence_library_ids
            | carried_library_ids
            | projected_component_ids
            | (set() if cohort else previously_measured_ids)
        )
        # ``run.aggregate`` intentionally emits a zero card for every configured
        # detector.  During phased onboarding that is not evidence.  Give the
        # portfolio builder only selected or previously measured cards so an
        # unselected detector remains explicitly unknown instead of becoming a
        # fabricated evaluated zero.
        portfolio = build_portfolio(
            [
                card for card in current["libraries"]
                if card.get("id") in measured_library_ids
            ],
            current["repos"],
        )
        current["libraries"] = portfolio["libraries"]
        current["repos"] = portfolio["repositories"]
        current["family_rollups"] = portfolio["family_rollups"]
        current["totals"].update(portfolio["totals"])
        legacy_cards = {
            card["id"]: card
            for card in legacy_current.get("libraries", ())
            if isinstance(card, Mapping) and isinstance(card.get("id"), str)
        }
        legacy_timeseries = _load_json(
            self.data_dir / "timeseries.json", {}
        ) if carried_library_ids else {}
        for card in current["libraries"]:
            library_id = card["id"]
            if library_id in carried_library_ids:
                old_card = legacy_cards.get(library_id) or {}
                if not cohort:
                    for field in (
                        "confirmed_count",
                        "bundled_count",
                        "targeted_count",
                        "headline_count",
                        "integration_ai_count",
                        "repo_ai_count",
                        "first_seen_earliest",
                        "trending_30d",
                        "trending_90d",
                        "growth_90d",
                        "growth_365d",
                        "sparkline",
                        "sparkline_months",
                        "classification_coverage",
                    ):
                        if field in old_card:
                            card[field] = copy.deepcopy(old_card[field])
                if library_id in legacy_timeseries:
                    timeseries[library_id] = copy.deepcopy(
                        legacy_timeseries[library_id]
                    )
            card.setdefault("tier", card.get("category", "portfolio"))
            card.setdefault(
                "description",
                (
                    "Metric contract pending."
                    if card.get("metric_contract_status") == "pending"
                    else "%s direct integration." % card.get("name", card["id"])
                ),
            )
            card.setdefault("released_on", card.get("first_observed_on", "2026-07")[:7])
            card.setdefault("released_confidence", "catalog")
            card.setdefault("language", "mixed")
            card.setdefault("sparkline", [])
            card.setdefault("sparkline_months", [])
            card.setdefault("adoption_counts_build", False)
            card.setdefault("bundled_label", None)
            card.setdefault("integration_ai_count", 0)
            card.setdefault("repo_ai_count", 0)
            card.setdefault("first_seen_earliest", None)
            card.setdefault("trending_30d", 0)
            card.setdefault("trending_90d", 0)
            card.setdefault("growth_90d", None)
            card.setdefault("growth_365d", None)
            card.setdefault("citation_growth_90d", None)
            card.setdefault("citation_growth_365d", None)
            card.setdefault("coverage_gaps", 0)
            card.setdefault("scan_capped", None)
            card.setdefault("delta_since_last", 0)
            timeseries.setdefault(card["id"], {
                "released_on": card["released_on"],
                "released_confidence": card["released_confidence"],
                "points": [],
            })
            discovery_stats.setdefault(card["id"], {
                "evidence_kind": "not-evaluated",
                "coverage_gaps": [],
                "sources": {},
                "source_lag_max_seconds": None,
                "stale": True,
                "carried_forward": False,
            })
        from .nvpl_rollup import apply_nvpl_additive_rollup
        apply_nvpl_additive_rollup(current, timeseries, current["repos"])
        for library_id, series in timeseries.items():
            if not isinstance(series, dict):
                continue
            if library_id not in carried_library_ids:
                series.setdefault("as_of", str(current["generated_at"])[:10])
        current["discovery_stats"] = discovery_stats
        current["scan_quality"] = dict(scan_quality)
        current["migration_quality"] = {
            "mixed_v1_v2": bool(carried_library_ids),
            "stale": bool(carried_library_ids),
            "carried_forward_library_ids": sorted(carried_library_ids),
            "selected_library_ids": sorted(set(selected_library_ids)),
            "legacy_as_of": legacy_current.get("generated_at"),
        }
        if cohort:
            selected = sorted(selected_library_ids)
            excluded = sorted(
                {library["id"] for library in libraries}
                - selected_library_ids
            )
            if (
                selected != cohort_contract["selected_library_ids"]
                or excluded != cohort_contract["excluded_library_ids"]
            ):
                raise PipelineError(
                    "partial-cohort materialization scope changed"
                )
            # Family-aware portfolio construction may derive a component floor
            # for an unselected parent. The release contract is stricter:
            # every deferred active detector remains explicitly unevaluated.
            cards_by_id = {
                card["id"]: card for card in current["libraries"]
            }
            for library_id in excluded:
                card = cards_by_id[library_id]
                card["collection_status"] = "not_collected"
                card["classification_coverage"] = {
                    classification: "not_evaluated"
                    for classification in (
                        "confirmed",
                        "bundled",
                        "targeted",
                    )
                }
                card["not_evaluated_classes"] = [
                    "bundled",
                    "confirmed",
                    "targeted",
                ]
                for field in (
                    "confirmed_count",
                    "bundled_count",
                    "targeted_count",
                    "headline_count",
                ):
                    card[field] = None
            current["release_metadata"] = {
                "scope": "partial-portfolio",
                "label": "Phase 8 Cohort A",
                "run_class": "phase8-cohort-a",
                "portfolio_complete": False,
            }
            current["portfolio_coverage"] = {
                "selected_library_ids": selected,
                "excluded_library_ids": excluded,
            }
        current["method_version"] = "2.0"
        current["fingerprints"] = self._active_plan.fingerprints.as_dict()
        current["catalog"] = {
            "source": "https://developer.nvidia.com/cuda/cuda-x-libraries",
            "observed_on": "2026-07-27",
            "entries": len(CATALOG),
        }
        return current, timeseries

    def _citations(
        self,
        state,
        current,
        budgets,
        *,
        run_deadline=None,
        cohort_contract=None,
    ):
        from .citation_pipeline import (
            CFF_ANALYSIS_FP,
            CitationPipeline,
            OpenAlexCitationSource,
            RepositoryCFF,
        )
        pipeline = self.citation_pipeline
        if pipeline is None:
            pipeline = CitationPipeline(state, OpenAlexCitationSource())
        elif callable(pipeline) and not hasattr(pipeline, "refresh"):
            pipeline = pipeline(state)
        confirmed = defaultdict(set)
        for repo in current["repos"]:
            for entry in repo["libraries"]:
                if (
                    entry["classification"] == "confirmed"
                    and entry.get("carried_forward") is not True
                ):
                    confirmed[entry["library_id"]].add(repo["full_name"])
        selected_ids = (
            set(cohort_contract["selected_library_ids"])
            if cohort_contract is not None
            else {library["id"] for library in config.LIBRARIES}
        )
        selected_citation_libraries = [
            library
            for library in config.LIBRARIES
            if (
                library["id"] in selected_ids
                and library.get("citation_query")
            )
        ]
        current_confirmed_names = {
            name for names in confirmed.values() for name in names
        }
        cff = []
        active_plan = getattr(self, "_active_plan", None)
        ai_fp = (
            active_plan.fingerprints.ai
            if active_plan is not None
            else None
        )
        query = """
            SELECT r.node_id, r.full_name, r.head_sha, a.analysis_json
            FROM repositories r JOIN repo_analysis a
              ON a.repository_id=r.node_id AND a.head_sha=r.head_sha
            WHERE a.status='clean' AND a.ai_fp%s
            """ % ("=?" if ai_fp is not None else "!=?")
        for row in state.connection.execute(
            query,
            (ai_fp if ai_fp is not None else CFF_ANALYSIS_FP,),
        ):
            if (
                cohort_contract is not None
                and row["full_name"] not in current_confirmed_names
            ):
                continue
            analysis = json.loads(row["analysis_json"])
            texts = analysis.get("citation_cff", {}) or {}
            cff.append(RepositoryCFF(
                repository_id=row["node_id"],
                full_name=row["full_name"],
                head_sha=row["head_sha"],
                text="\n".join(
                    str(texts[path]) for path in sorted(texts)
                ),
            ))
        result = pipeline.refresh(
            selected_citation_libraries,
            repository_cff=cff,
            confirmed_repositories=confirmed,
            max_openalex_requests=budgets.max_openalex_requests,
            max_source_extractions=budgets.max_citation_source_extractions,
            deadline_monotonic=run_deadline,
        )
        raw_metrics = getattr(result, "metrics", {}) or {}
        self._citation_metrics = {
            str(key): value
            for key, value in sorted(raw_metrics.items())
            if isinstance(value, (bool, int, float, str)) or value is None
        }
        self._citation_metrics.update(
            {
                "libraries_requested": len(
                    selected_citation_libraries
                ),
                "repositories_with_cff": len(cff),
                "used_last_good": bool(
                    getattr(result, "used_last_good", False)
                ),
                "all_failed": bool(
                    getattr(result, "all_failed", False)
                ),
            }
        )
        document = copy.deepcopy(result.document)
        document.setdefault("libraries", {})
        document.setdefault("coverage", {})
        document.setdefault("errors", {})
        # V1 is the final per-library safety net during the first V2 run.  A
        # partial OpenAlex failure must not erase a good historical library
        # merely because another library refreshed successfully.
        old = _load_json(self.data_dir / "citations.json", {})
        wanted_ids = {
            library["id"] for library in selected_citation_libraries
        }
        for library_id, old_value in sorted((old.get("libraries") or {}).items()):
            if (
                library_id not in wanted_ids
                or library_id in document["libraries"]
                or not isinstance(old_value, dict)
            ):
                continue
            value = copy.deepcopy(old_value)
            value["stale"] = True
            errors = list(value.get("errors") or ())
            message = "citation refresh failed; V1 last-good carried forward"
            if message not in errors:
                errors.append(message)
            value["errors"] = errors
            coverage = value.get("coverage")
            if not isinstance(coverage, dict):
                coverage = {}
                value["coverage"] = coverage
            coverage.update(
                {
                    "stale": True,
                    "complete": False,
                    "carried_forward": True,
                    "source": coverage.get("source", old.get("source", "V1")),
                    "errors": errors,
                }
            )
            document["libraries"][library_id] = value
            document["coverage"][library_id] = coverage
            document["errors"][library_id] = errors
        if document["libraries"]:
            document["stale"] = bool(
                document.get("stale")
                or any(
                    value.get("stale")
                    for value in document["libraries"].values()
                    if isinstance(value, dict)
                )
            )
            return document
        # An all-failed first V2 citation stage with no per-library V1 fallback
        # cannot manufacture a publishable citation artifact.
        if (
            getattr(result, "all_failed", False)
            and not (old.get("libraries") or {})
        ):
            raise PipelineError(
                "all citation lanes failed and no last-good citation data exists"
            )
        return old

    def run(
        self,
        *,
        mode,
        confirm_full=False,
        library_ids: Iterable[str] = (),
        budgets: RunBudgets | None = None,
        reviewed_execution_contract: Mapping[str, Any] | None = None,
    ):
        if mode not in ("refresh", "reconcile", "onboard"):
            raise ValueError("unsupported pipeline mode")
        if mode == "reconcile" and not confirm_full:
            raise PipelineError("reconcile requires --confirm-full")
        wanted = set(library_ids)
        unknown = wanted - {lib["id"] for lib in config.LIBRARIES}
        if unknown:
            raise PipelineError("unknown library IDs: %s" % ", ".join(sorted(unknown)))
        all_libraries = list(config.LIBRARIES)
        selected_libraries = [
            lib for lib in config.LIBRARIES
            if not wanted or lib["id"] in wanted
        ]
        if mode == "onboard" and not wanted:
            raise PipelineError("onboard requires at least one --libraries ID")
        libraries = all_libraries
        budgets = budgets or (
            RunBudgets.reconcile() if mode == "reconcile" else RunBudgets.weekly()
        )
        cohort_contract = _validate_reviewed_execution_contract(
            reviewed_execution_contract,
            mode=mode,
            wanted=wanted,
            budgets=budgets,
            metadata_batch_size=self._metadata_batch_size(),
        )
        cohort = cohort_contract is not None
        self._restore_state_checkpoint_if_needed()
        # Recover a power-interrupted publication before fingerprints/counts
        # are planned against the last-good release.
        if self._publication_journal_path.exists():
            recovery_owner = "recovery:%s:%d" % (
                socket.gethostname(),
                os.getpid(),
            )
            with StateDB(self.state_path) as recovery_state:
                if not recovery_state.acquire_lock(
                    "collector-network-run",
                    owner=recovery_owner,
                    lease_seconds=300,
                ):
                    raise PipelineError(
                        "another collector run owns publication recovery"
                    )
                try:
                    self._recover_publication(recovery_state)
                finally:
                    recovery_state.release_lock(
                        "collector-network-run", owner=recovery_owner
                    )
        plan_mode = "reconcile" if mode == "reconcile" else "refresh"
        plan = build_plan(
            mode=plan_mode,
            state_path=self.state_path,
            data_dir=self.data_dir,
            libraries=all_libraries,
            weekly_scan_budget=budgets.max_scan_repositories,
            max_graphql_points=budgets.max_graphql_points,
            min_graphql_remaining=budgets.min_graphql_remaining,
        )
        if mode == "refresh" and plan.requires_full_confirmation:
            raise BudgetExceeded(
                "weekly refresh refused unbounded invalidation; run "
                "`python3 -m collector.cli reconcile --confirm-full` after review"
            )
        self._active_plan = plan
        execution_contract = cohort_contract or {
            "mode": mode,
            "selected_library_ids": sorted(
                wanted or {lib["id"] for lib in selected_libraries}
            ),
            "metadata_batch_size": self._metadata_batch_size(),
            "network_task_source_sha256": (
                _network_task_source_sha256()
            ),
        }
        run_class = execution_contract.get("run_class")
        release_scope = execution_contract.get("release_scope")
        historical_wall_seconds = float(
            execution_contract.get("historical_wall_seconds", 0) or 0
        )
        started = self.clock() - historical_wall_seconds
        cache_before_reader = (
            RepoCache(
                self.cache_root,
                target_bytes=budgets.cache_target_bytes,
                hard_bytes=budgets.cache_hard_bytes,
            )
            if self.cache_root.exists()
            else None
        )
        cache_before_bytes = (
            cache_before_reader.size_bytes() if cache_before_reader else 0
        )
        cache_before_keys = frozenset(
            str(item["key"]) for item in cache_before_reader.entries()
        ) if cache_before_reader else frozenset()
        run_deadline = started + budgets.max_wall_seconds
        owner = "%s:%d:%s" % (socket.gethostname(), os.getpid(), uuid.uuid4().hex[:8])
        run_id = datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]

        with StateDB(self.state_path) as state:
            heartbeat = None
            v2_transaction = None
            checkpoint_transaction = None
            release_id = None
            artifacts: list[dict[str, Any]] = []
            lock_lease = 300
            if not state.acquire_lock(
                "collector-network-run",
                owner=owner,
                lease_seconds=lock_lease,
            ):
                raise PipelineError("another collector network run owns the state lock")
            try:
                heartbeat = _RunLockHeartbeat(
                    self.state_path,
                    "collector-network-run",
                    owner,
                    lock_lease,
                )
                heartbeat.start()
                base_release_id = self._run_base_release_id()
                try:
                    resumed_run_id = state.resume_compatible_run(
                        mode=mode,
                        budgets=budgets.to_dict(),
                        fingerprints=plan.fingerprints.as_dict(),
                        base_release_id=base_release_id,
                        execution_contract=execution_contract,
                    )
                except RuntimeError as exc:
                    raise PipelineError(str(exc)) from exc
                if resumed_run_id is not None:
                    run_id = resumed_run_id
                else:
                    state.create_run(
                        run_id,
                        mode=mode,
                        plan={
                            **plan.to_dict(),
                            "execution_contract": execution_contract,
                        },
                        budgets=budgets.to_dict(),
                        fingerprints=plan.fingerprints.as_dict(),
                        base_release_id=base_release_id,
                        status="running",
                    )
                prior_final_stage = state.connection.execute(
                    """
                    SELECT status FROM stages
                    WHERE run_id=? AND stage='final_visibility'
                    """,
                    (run_id,),
                ).fetchone()
                prior_final_status = (
                    prior_final_stage["status"]
                    if prior_final_stage is not None
                    else None
                )
                fresh_metadata_rows = list(state.connection.execute(
                    """
                    SELECT task_key,status FROM tasks
                    WHERE run_id=? AND stage='github-metadata-batch'
                      AND task_key LIKE 'fresh:%'
                    ORDER BY task_id
                    """,
                    (run_id,),
                ))
                reusable_fresh_metadata_epoch = False
                if fresh_metadata_rows:
                    newest_fresh_epoch = str(
                        fresh_metadata_rows[-1]["task_key"]
                    ).split(":", 2)[1]
                    newest_fresh_rows = [
                        row for row in fresh_metadata_rows
                        if str(row["task_key"]).split(":", 2)[1]
                        == newest_fresh_epoch
                    ]
                    reusable_fresh_metadata_epoch = bool(
                        newest_fresh_rows
                    ) and all(
                        row["status"] == "complete"
                        for row in newest_fresh_rows
                    )
                force_metadata_refresh = (
                    _should_force_metadata_refresh_after_final_visibility(
                        resumed_run=resumed_run_id is not None,
                        prior_stage_status=prior_final_status,
                        reusable_fresh_metadata_epoch=(
                            reusable_fresh_metadata_epoch
                        ),
                        visibility_rejection_resume_control=(
                            cohort_contract.get(
                                "visibility_rejection_resume_control"
                            )
                            if cohort_contract
                            else None
                        ),
                    )
                )
                allow_final_visibility_resume = (
                    _should_resume_final_visibility_epoch(
                        resumed_run=resumed_run_id is not None,
                        prior_stage_status=prior_final_status,
                        final_visibility_privacy_control=(
                            cohort_contract.get(
                                "final_visibility_privacy_control"
                            )
                            if cohort_contract else None
                        ),
                    )
                )
                catalog = _catalog_index()
                for lib in all_libraries:
                    state.upsert_library(
                        lib["id"],
                        catalog={
                            **catalog.get(lib["id"], {}),
                            "detector": json.loads(fingerprint_json(dict(lib))),
                        },
                        fingerprints=_library_fp_values(plan, lib["id"]),
                    )
                executable_ids = {lib["id"] for lib in all_libraries}
                for item in CATALOG:
                    if item["id"] in executable_ids:
                        continue
                    state.upsert_library(
                        item["id"],
                        catalog=dict(item),
                        fingerprints=_catalog_only_fp_values(item),
                        active=False,
                    )
                state.record_catalog_events(CATALOG_EVENTS)
                self._durable_discovery_usage = (
                    self._charge_prior_discovery_usage(state, run_id)
                )
                state.update_stage(run_id, "discovery", status="running")
                observations, discovery_metrics = self._discover(
                    state,
                    run_id,
                    selected_libraries,
                    mode,
                    budgets,
                    run_deadline=run_deadline,
                )
                state.update_stage(
                    run_id,
                    "discovery",
                    status="complete",
                    counters={"observations": len(observations)},
                    metrics=discovery_metrics,
                )
                heartbeat.verify(state)
                self._check_time(started, budgets)

                legacy = _legacy_candidates(self.data_dir)
                state_candidates, state_known = _state_candidates(state)
                state.update_stage(run_id, "metadata", status="running")
                resolution, publishable, by_name, by_node = self._resolve_metadata(
                    state,
                    observations,
                    legacy,
                    state_known,
                    run_id=run_id,
                    budgets=budgets,
                    run_deadline=run_deadline,
                    force_refresh=force_metadata_refresh,
                    reuse_completed_epoch=(
                        not force_metadata_refresh
                        and (
                            allow_final_visibility_resume
                            or bool(
                                cohort_contract
                                and cohort_contract.get(
                                    "preseeded_metadata_epoch"
                                )
                            )
                        )
                    ),
                    preseeded_epoch_contract=(
                        cohort_contract.get("preseeded_metadata_epoch")
                        if (
                            cohort_contract
                            and not force_metadata_refresh
                            and cohort_contract.get(
                                "visibility_resume_control"
                            ) is None
                        )
                        else None
                    ),
                    resume_incomplete_fresh_epoch=(
                        bool(
                            cohort_contract
                            and cohort_contract.get(
                                "visibility_epoch_recovery_control"
                            )
                        )
                        or _should_resume_incomplete_fresh_metadata_epoch(
                            force_metadata_refresh=force_metadata_refresh,
                            graphql_resume_control=(
                                cohort_contract.get("graphql_resume_control")
                                if cohort_contract else None
                            ),
                        )
                    ),
                    resume_fresh_metadata_epoch=(
                        cohort_contract[
                            "visibility_epoch_recovery_control"
                        ]["resume_metadata_epoch"]
                        if cohort_contract
                        and cohort_contract.get(
                            "visibility_epoch_recovery_control"
                        )
                        else None
                    ),
                    post_refresh_privacy_control=(
                        cohort_contract.get(
                            "post_refresh_privacy_control"
                        )
                        if cohort_contract
                        else None
                    ),
                    final_visibility_privacy_control=(
                        cohort_contract.get(
                            "final_visibility_privacy_control"
                        )
                        if cohort_contract
                        else None
                    ),
                )
                persisted_legacy = legacy
                persisted_state_candidates = state_candidates
                if cohort:
                    persisted_legacy = {
                        name: set(library_ids) & wanted
                        for name, library_ids in legacy.items()
                        if set(library_ids) & wanted
                    }
                    persisted_state_candidates = {
                        name: set(library_ids) & wanted
                        for name, library_ids in state_candidates.items()
                        if set(library_ids) & wanted
                    }
                grouped = self._persist_candidates(
                    state,
                    run_id,
                    observations,
                    persisted_legacy,
                    persisted_state_candidates,
                    publishable,
                    by_name,
                    by_node,
                )
                if (
                    cohort_contract
                    and cohort_contract.get("privacy_resume_control")
                ):
                    publishable = _pin_phase8_scan_bound_metadata(
                        state,
                        run_id,
                        publishable,
                        cohort_contract,
                    )
                if mode == "onboard" or cohort:
                    grouped = {
                        name: set(ids) & wanted
                        for name, ids in grouped.items()
                        if set(ids) & wanted
                    }
                self._scan_tail_deferral_metrics = {}
                if cohort_contract and cohort_contract.get(
                    "scan_tail_deferral"
                ):
                    grouped, self._scan_tail_deferral_metrics = (
                        _apply_phase8_scan_tail_deferral(
                            state,
                            run_id,
                            grouped,
                            publishable,
                            cohort_contract,
                        )
                    )
                state.update_stage(
                    run_id,
                    "metadata",
                    status="complete",
                    counters={
                        "resolved": len(resolution.repositories),
                        "publishable": len(publishable),
                    },
                    metrics={
                        "graphql_requests": resolution.request_count,
                        "graphql_points": resolution.points_used,
                        "graphql_remaining": resolution.remaining,
                        "candidate_identity": dict(
                            getattr(
                                self,
                                "_candidate_identity_metrics",
                                {},
                            )
                        ),
                        **getattr(
                            self, "_metadata_task_metrics", {}
                        ),
                    },
                )
                heartbeat.verify(state)
                self._check_time(started, budgets)

                redated_count = 0
                if plan.invalidation.redate_all_positives:
                    state.update_stage(run_id, "redate", status="running")
                    redated_count = self._redate(
                        state,
                        run_id,
                        plan.fingerprints.dating,
                    )
                    state.update_stage(
                        run_id,
                        "redate",
                        status="complete",
                        counters={"redated": redated_count},
                    )
                    heartbeat.verify(state)
                    self._check_time(started, budgets)

                state.update_stage(run_id, "scan", status="running")
                outcomes, scan_count = self._scan(
                    state,
                    run_id,
                    selected_libraries,
                    grouped,
                    publishable,
                    budgets,
                    retirement_library_ids=(
                        _retirement_eligible_library_ids(
                            selected_libraries,
                            discovery_metrics,
                        )
                    ),
                    run_deadline=run_deadline,
                    retry_workers=_issue_retry_workers(
                        run_class, budgets
                    ),
                    defer_issue_lane=(run_class == "phase8-cohort-a"),
                    # The owner-deferred rows remain part of this run's
                    # certified immutable task universe even though they are
                    # deliberately absent from ``grouped``.  Generic task
                    # replanning must not misclassify those omitted failures
                    # as superseded completions.
                    preserve_task_universe=bool(
                        self._scan_tail_deferral_metrics
                    ),
                    allow_scan_bound_renames=bool(
                        cohort_contract
                        and cohort_contract.get("privacy_resume_control")
                    ),
                    fresh_candidate_deferral_control=(
                        _validate_phase8_fresh_candidate_deferral_control(
                            cohort_contract[
                                "fresh_candidate_deferral_control"
                            ],
                            cohort_contract["privacy_resume_control"],
                        )
                        if cohort_contract
                        and cohort_contract.get(
                            "fresh_candidate_deferral_control"
                        )
                        else None
                    ),
                    post_refresh_privacy_control=(
                        cohort_contract.get(
                            "post_refresh_privacy_control"
                        )
                        if cohort_contract
                        else None
                    ),
                )
                git_materialized_bytes = int(
                    self._scan_attempt_usage.get(
                        "network_materialized_bytes", 0
                    )
                )
                if (
                    git_materialized_bytes
                    > budgets.max_git_materialized_bytes
                ):
                    raise BudgetExceeded(
                        "Git materialization byte budget exhausted "
                        "(%d > %d)"
                        % (
                            git_materialized_bytes,
                            budgets.max_git_materialized_bytes,
                        )
                    )
                classifications = _scan_classification_inventory(outcomes)
                state.update_stage(
                    run_id,
                    "scan",
                    status="complete",
                    counters={
                        "selected": scan_count,
                        **dict(self._scan_selection_metrics),
                        "matches": sum(x.status == "match" for x in outcomes),
                        "clean_rejects": sum(x.status == "clean_reject" for x in outcomes),
                        "errors": sum(x.status == "error" for x in outcomes),
                        "cache_hits": sum(bool(x.cache_hit) for x in outcomes),
                        "attempts": int(
                            self._scan_attempt_usage.get(
                                "attempt_count", 0
                            )
                        ),
                        "clones": int(
                            self._scan_attempt_usage.get(
                                "network_clone_count", 0
                            )
                        ),
                        "fetches": int(
                            self._scan_attempt_usage.get(
                                "network_fetch_count", 0
                            )
                        ),
                        "classifications": classifications["totals"],
                    },
                    metrics={
                        **dict(self._scan_selection_metrics),
                        **dict(self._scan_tail_deferral_metrics),
                        "scan_seconds": round(sum(x.seconds for x in outcomes), 3),
                        "files_examined": sum(x.files_examined for x in outcomes),
                        "bytes_examined": sum(x.bytes_examined for x in outcomes),
                        "skipped_large_files": sum(
                            x.skipped_large_files for x in outcomes
                        ),
                        "pruned_large_assets": sum(
                            x.pruned_large_assets for x in outcomes
                        ),
                        "cache_entry_bytes": sum(x.cache_bytes for x in outcomes),
                        "git_materialized_bytes": git_materialized_bytes,
                        "attempt_usage": dict(
                            self._scan_attempt_usage
                        ),
                        "classifications": classifications,
                        "current_tree_triage_seconds": round(
                            sum(
                                x.current_tree_triage_seconds
                                for x in outcomes
                            ),
                            3,
                        ),
                        "history_dating_seconds": round(
                            sum(
                                x.history_dating_seconds
                                for x in outcomes
                            ),
                            3,
                        ),
                        "analysis_seconds": round(
                            sum(x.analysis_seconds for x in outcomes), 3
                        ),
                        "git_subprocess_count": sum(
                            x.git_subprocess_count for x in outcomes
                        ),
                    },
                )
                heartbeat.verify(state)
                self._check_time(started, budgets)

                scan_quality = {
                    "mode": mode,
                    "run_class": run_class,
                    "coverage_claim": (
                        "partial-cohort-owner-deferred-tail"
                        if self._scan_tail_deferral_metrics
                        else (
                            "partial-cohort-reconcile"
                            if cohort
                            else (
                                "complete-reconcile"
                                if mode == "reconcile"
                                else "bounded-run"
                            )
                        )
                    ),
                    "selected_repositories": scan_count,
                    "files_examined": sum(x.files_examined for x in outcomes),
                    "bytes_examined": sum(x.bytes_examined for x in outcomes),
                    "skipped_large_files": sum(
                        x.skipped_large_files for x in outcomes
                    ),
                    "pruned_large_assets": sum(
                        x.pruned_large_assets for x in outcomes
                    ),
                    "policy": dict(SCAN_POLICY),
                    "freshness": dict(SCAN_FRESHNESS),
                    **dict(self._scan_tail_deferral_metrics),
                }
                scan_quality["complete"] = (
                    scan_quality["skipped_large_files"] == 0
                    and not self._scan_tail_deferral_metrics
                )
                if (
                    not scan_quality["complete"]
                    and not self._scan_tail_deferral_metrics
                ):
                    raise PipelineError(
                        "collection skipped oversized own-source files; "
                        "last-good release preserved"
                    )
                state.update_stage(run_id, "aggregation", status="running")
                current, timeseries = self._materialize(
                    state,
                    all_libraries,
                    discovery_metrics,
                    mode=mode,
                    selected_library_ids=wanted or {
                        lib["id"] for lib in selected_libraries
                    },
                    scan_quality=scan_quality,
                    cohort_contract=cohort_contract,
                )
                state.update_stage(
                    run_id,
                    "aggregation",
                    status="complete",
                    counters={
                        "libraries": len(current.get("libraries", ())),
                        "repositories": len(current.get("repos", ())),
                        "timeseries": len(timeseries),
                    },
                )
                heartbeat.verify(state)
                self._check_time(started, budgets)

                state.update_stage(run_id, "citations", status="running")
                citations = self._citations(
                    state,
                    current,
                    budgets,
                    run_deadline=run_deadline,
                    cohort_contract=cohort_contract,
                )
                state.update_stage(
                    run_id,
                    "citations",
                    status="complete",
                    counters={
                        "libraries": len(citations.get("libraries", {})),
                        "errors": len(citations.get("errors", {})),
                    },
                    metrics=dict(self._citation_metrics),
                )
                heartbeat.verify(state)
                self._check_time(started, budgets)
                self._check_slo(
                    mode=mode,
                    scans=scan_count,
                    started=started,
                    budgets=budgets,
                    run_class=run_class,
                )
                deltas = _prior_diff(current, self.data_dir)
                state.update_stage(run_id, "publication", status="running")
                with stage_v2(
                    current,
                    timeseries,
                    citations,
                    deltas,
                    self.data_dir / "v2",
                ) as staged:
                    manifest = staged.manifest
                    release_id = manifest["release"]["id"]
                    artifacts = _artifact_inventory(staged.root, "data/v2")
                    publication_counters = {
                        "libraries": len(manifest["libraries"]),
                        "repositories": manifest["totals"].get(
                            "confirmed_integrator_repos", 0
                        ),
                    }
                    journal = {
                        "version": 1,
                        "phase": "staged",
                        "run_id": run_id,
                        "release_id": release_id,
                        "artifacts": artifacts,
                        "counters": publication_counters,
                    }
                    # This is the last-good gate.  No live V2 pointer has
                    # changed, and staging has already passed universal
                    # validation.
                    heartbeat.verify(state)
                    self._check_slo(
                        mode=mode,
                        scans=scan_count,
                        started=started,
                        budgets=budgets,
                        run_class=run_class,
                    )
                    state.update_stage(
                        run_id,
                        "final_visibility",
                        status="running",
                    )
                    try:
                        final_visibility = (
                            self._reattest_final_visibility(
                                state,
                                run_id,
                                current,
                                resolution,
                                budgets,
                                run_deadline=run_deadline,
                                allow_resume=(
                                    allow_final_visibility_resume
                                ),
                                final_visibility_privacy_control=(
                                    cohort_contract.get(
                                        "final_visibility_privacy_control"
                                    )
                                    if cohort_contract
                                    else None
                                ),
                            )
                        )
                    except BaseException:
                        state.update_stage(
                            run_id,
                            "final_visibility",
                            status="failed",
                        )
                        raise
                    state.update_stage(
                        run_id,
                        "final_visibility",
                        status="complete",
                        counters={
                            "repositories": final_visibility[
                                "repository_count"
                            ],
                            "batches": final_visibility["batch_count"],
                        },
                        metrics=final_visibility,
                        checkpoint={
                            "set_sha256": final_visibility["set_sha256"],
                            "checked_at": final_visibility["checked_at"],
                        },
                    )
                    journal["final_visibility"] = {
                        key: final_visibility[key]
                        for key in (
                            "set_sha256",
                            "checked_at",
                            "epoch_completed_at",
                            "repository_count",
                            "graphql_requests",
                            "graphql_points",
                            "graphql_remaining",
                        )
                    }
                    heartbeat.verify(state)
                    self._check_time(started, budgets)
                    state.assert_run_publishable(run_id)
                    state.record_release(
                        release_id,
                        run_id=run_id,
                        state_txn=run_id,
                        manifest_path="data/v2/manifest.json",
                        artifacts=artifacts,
                        validation={"valid": True, "errors": []},
                        status="staged",
                    )
                    self._write_publication_journal(**journal)
                    # Publish a resumable staged checkpoint first. The V2
                    # manifest remains the external commit pointer; a crash
                    # before it changes restores this prior checkpoint.
                    with tempfile.TemporaryDirectory(
                        prefix=".state-checkpoint-staging-",
                        dir=self.data_dir,
                    ) as checkpoint_temporary:
                        staged_checkpoint = (
                            Path(checkpoint_temporary) / "state-checkpoint"
                        )
                        state.export_checkpoint_shards(staged_checkpoint)
                        heartbeat.verify(state)
                        self._check_slo(
                            mode=mode,
                            scans=scan_count,
                            started=started,
                            budgets=budgets,
                            run_class=run_class,
                        )
                        checkpoint_swap = _DirectorySwap(
                            staged_checkpoint,
                            self.data_dir / "state-checkpoint",
                        )
                        journal.update(
                            {
                                "phase": "checkpoint_installing",
                                "checkpoint_backup": str(
                                    checkpoint_swap.backup
                                ),
                                "checkpoint_had_live": (
                                    self.data_dir / "state-checkpoint"
                                ).exists(),
                            }
                        )
                        self._write_publication_journal(**journal)
                        checkpoint_transaction = checkpoint_swap.install()
                        journal["phase"] = "checkpoint_installed"
                        self._write_publication_journal(**journal)
                        heartbeat.verify(state)
                        self._check_slo(
                            mode=mode,
                            scans=scan_count,
                            started=started,
                            budgets=budgets,
                            run_class=run_class,
                        )

                        # Install V2 manifest-last. Once the manifest names this
                        # release, startup recovery always rolls forward.
                        final_visibility[
                            "oldest_attestation_age_seconds"
                        ] = round(
                            _assert_final_visibility_fresh(
                                final_visibility
                            ),
                            3,
                        )
                        state.update_stage(
                            run_id,
                            "final_visibility",
                            status="complete",
                            counters={
                                "repositories": final_visibility[
                                    "repository_count"
                                ],
                                "batches": final_visibility["batch_count"],
                            },
                            metrics=final_visibility,
                            checkpoint={
                                "set_sha256": final_visibility[
                                    "set_sha256"
                                ],
                                "checked_at": final_visibility["checked_at"],
                            },
                        )
                        v2_transaction = staged.provisional_install(
                            self.data_dir / "v2"
                        )
                        journal.update(
                            {
                                "phase": "v2_installed",
                                "v2_quarantine": str(
                                    v2_transaction.quarantine
                                ),
                            }
                        )
                        self._write_publication_journal(**journal)
                        heartbeat.verify(state)

                        state.update_stage(
                            run_id,
                            "publication",
                            status="complete",
                            counters=publication_counters,
                            metrics={
                                "manifest_bytes": (
                                    staged.root / "manifest.json"
                                ).stat().st_size,
                            },
                        )
                        runtime_report = self._runtime_report(
                            mode=mode,
                            run_class=run_class,
                            release_scope=release_scope,
                            started=started,
                            budgets=budgets,
                            outcomes=outcomes,
                            cache_before_bytes=cache_before_bytes,
                            cache_before_keys=cache_before_keys,
                            discovery_metrics=discovery_metrics,
                            resolution=resolution,
                            final_visibility=final_visibility,
                            artifacts=artifacts,
                            stage_durations=_stage_duration_inventory(
                                state, run_id
                            ),
                            task_inventory=_task_runtime_inventory(
                                state, run_id
                            ),
                        )
                        state.update_stage(
                            run_id,
                            "final_report",
                            status="complete",
                            counters={
                                "selected": scan_count,
                                "unresolved": int(
                                    self._scan_tail_deferral_metrics.get(
                                        "deferred_repositories", 0
                                    )
                                ),
                            },
                            metrics=runtime_report,
                        )
                        state.finish_run(run_id, status="complete")
                        state.record_release(
                            release_id,
                            run_id=run_id,
                            state_txn=run_id,
                            manifest_path="data/v2/manifest.json",
                            artifacts=artifacts,
                            validation={"valid": True, "errors": []},
                            status="published",
                        )
                        state.compact_operational_history()
                        journal["phase"] = "state_published"
                        self._write_publication_journal(**journal)

                        # Regenerate after the final state transition so the
                        # durable checkpoint itself says complete/published.
                        final_checkpoint = (
                            Path(checkpoint_temporary)
                            / "final-state-checkpoint"
                        )
                        state.export_checkpoint_shards(final_checkpoint)
                        final_transaction = _DirectorySwap(
                            final_checkpoint,
                            self.data_dir / "state-checkpoint",
                        ).install()
                        final_transaction.commit()
                        checkpoint_transaction.commit()
                        checkpoint_transaction = None
                        v2_transaction.commit()
                        v2_transaction = None
                        self._clear_publication_journal()
                    return {
                        "run_id": run_id,
                        "release_id": release_id,
                        "plan": plan.to_dict(),
                        "scanned": scan_count,
                        "redated": redated_count,
                        "manifest": manifest,
                        "report": runtime_report,
                    }
            except BaseException:
                rollback_ok = True
                if v2_transaction is not None:
                    try:
                        v2_transaction.rollback()
                    except Exception:
                        rollback_ok = False
                if checkpoint_transaction is not None:
                    try:
                        checkpoint_transaction.rollback()
                    except Exception:
                        rollback_ok = False
                if rollback_ok:
                    try:
                        v2_root = self.data_dir / "v2"
                        if (v2_root / "manifest.json").exists():
                            _close_and_validate_v2(v2_root)
                        checkpoint_root = (
                            self.data_dir / "state-checkpoint"
                        )
                        if checkpoint_root.exists():
                            checkpoint_document = (
                                state._read_sharded_checkpoint(checkpoint_root)
                            )
                            state._validate_checkpoint(checkpoint_document)
                    except Exception:
                        rollback_ok = False
                if rollback_ok:
                    self._clear_publication_journal()
                try:
                    if release_id is not None:
                        state.record_release(
                            release_id,
                            run_id=run_id,
                            state_txn=run_id,
                            manifest_path="data/v2/manifest.json",
                            artifacts=artifacts,
                            validation={
                                "valid": False,
                                "errors": ["publication transaction failed"],
                            },
                            status="rejected",
                        )
                    running_stages = tuple(
                        row["stage"]
                        for row in state.connection.execute(
                            """
                            SELECT stage FROM stages
                            WHERE run_id=? AND status='running'
                            ORDER BY stage
                            """,
                            (run_id,),
                        )
                    )
                    for failed_stage in running_stages:
                        state.update_stage(
                            run_id,
                            failed_stage,
                            status="failed",
                        )
                    if "publication" not in running_stages:
                        state.update_stage(
                            run_id,
                            "publication",
                            status="failed",
                        )
                    state.finish_run(run_id, status="failed")
                except Exception:
                    pass
                raise
            finally:
                if heartbeat is not None:
                    heartbeat.stop()
                state.release_lock("collector-network-run", owner=owner)
