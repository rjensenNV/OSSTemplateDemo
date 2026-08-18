"""REQ-14 command contract for the Mac-local collector."""

from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import subprocess
import sys
from pathlib import Path

from .pipeline import (
    BudgetExceeded,
    CollectorPipeline,
    PipelineError,
    RunBudgets,
    _RunLockHeartbeat,
)
from .planner import build_plan
from .state import StateDB
from .validate_v2 import validate_v2


def _format_bytes(value):
    amount = float(max(0, int(value)))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return ("%.1f %s" % (amount, unit)) if unit != "B" else ("%d B" % amount)
        amount /= 1024


def _libraries(value):
    if not value:
        return ()
    values = []
    for item in value:
        values.extend(part.strip() for part in item.split(",") if part.strip())
    return tuple(dict.fromkeys(values))


def _budget(args, mode):
    base = RunBudgets.reconcile() if mode == "reconcile" else RunBudgets.weekly()
    values = base.to_dict()
    for field in (
        "max_wall_seconds",
        "max_scan_repositories",
        "max_sourcegraph_requests",
        "max_github_search_requests",
        "max_graphql_points",
        "min_graphql_remaining",
        "max_fetches",
        "workers",
        "max_openalex_requests",
        "max_citation_source_extractions",
        "repo_timeout_seconds",
        "cache_target_bytes",
        "cache_hard_bytes",
        "max_git_materialized_bytes",
    ):
        value = getattr(args, field, None)
        if value is not None:
            values[field] = value
    return RunBudgets(**values)


def _add_budget_flags(parser):
    parser.add_argument("--max-wall-seconds", type=int)
    parser.add_argument("--max-scan-repositories", type=int)
    parser.add_argument("--max-sourcegraph-requests", type=int)
    parser.add_argument("--max-github-search-requests", type=int)
    parser.add_argument("--max-graphql-points", type=int)
    parser.add_argument("--min-graphql-remaining", type=int)
    parser.add_argument("--max-fetches", type=int)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--max-openalex-requests", type=int)
    parser.add_argument("--max-citation-source-extractions", type=int)
    parser.add_argument("--repo-timeout-seconds", type=int)
    parser.add_argument("--cache-target-bytes", type=int)
    parser.add_argument("--cache-hard-bytes", type=int)
    parser.add_argument("--max-git-materialized-bytes", type=int)


def _plan(args):
    root = Path(args.repo_root).resolve()
    state_path = root / args.state
    data_path = root / args.data
    budgets = _budget(args, args.mode)
    weekly_scan_budget = (
        args.weekly_scan_budget
        if args.weekly_scan_budget is not None
        else budgets.max_scan_repositories
    )
    plan = build_plan(
        mode=args.mode,
        state_path=state_path,
        data_dir=data_path,
        weekly_scan_budget=weekly_scan_budget,
        max_graphql_points=budgets.max_graphql_points,
        min_graphql_remaining=budgets.min_graphql_remaining,
    )
    document = plan.to_dict()
    document["budgets"] = budgets.to_dict()
    usage = shutil.disk_usage(root)
    cumulative_git = document["estimates"]["network_bytes"][
        "git_transfer_upper_estimate"
    ]
    cache_target = budgets.cache_target_bytes
    cache_hard = budgets.cache_hard_bytes
    operating_margin = 20 * 1024**3
    document["local_disk"] = {
        "free_bytes": usage.free,
        "total_bytes": usage.total,
        # Cumulative materialization can greatly exceed retained disk because
        # the LRU cache evicts clean rejects. Keep transfer/work and peak local
        # capacity separate in the owner-facing plan.
        "estimated_cumulative_git_materialization_bytes": cumulative_git,
        "retained_cache_target_bytes": cache_target,
        "retained_cache_hard_bytes": cache_hard,
        "retained_cache_growth_upper_bytes": min(
            cumulative_git, cache_hard
        ),
        "operating_margin_bytes": operating_margin,
        "hard_cache_headroom_bytes": (
            usage.free - cache_hard - operating_margin
        ),
        "hard_cache_plus_margin_fits": (
            usage.free >= cache_hard + operating_margin
        ),
    }
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        estimates = document["estimates"]
        print("REQ-14 %s plan" % args.mode)
        print("  state: %s" % ("cold" if plan.cold_state else "warm"))
        print(
            "  known repositories: %d"
            % max(
                plan.local_counts["known_repositories"],
                plan.local_counts["legacy_published_repositories"],
            )
        )
        print("  estimated scans: %d" % estimates["scans"])
        print(
            "  repositories with unknown GitHub size: %d"
            % estimates["repositories_with_unknown_size"]
        )
        print("  estimated GraphQL requests: %d" % estimates["graphql_requests"])
        print(
            "  discovery request floor: %d Sourcegraph + %d GitHub"
            % (
                estimates["sourcegraph_requests"],
                estimates["github_search_requests_floor"],
            )
        )
        network = estimates["network_bytes"]
        print(
            "  estimated network transfer: %s total (%s Git upper estimate)"
            % (
                _format_bytes(network["total"]),
                _format_bytes(network["git_transfer_upper_estimate"]),
            )
        )
        print("  estimated wall time: %d minutes" % estimates["wall_minutes"])
        print(
            "  workers: %d; wall budget: %d minutes"
            % (budgets.workers, budgets.max_wall_seconds // 60)
        )
        print(
            "  scan/fetch budgets: %d/%d"
            % (budgets.max_scan_repositories, budgets.max_fetches)
        )
        print("  disk free: %.1f GiB" % (usage.free / 1024**3))
        for repository in document["outliers"]["repositories"][:3]:
            size = repository["estimated_git_transfer_bytes_upper_bound"]
            print(
                "  repository outlier: %s (%s; %d active candidates)"
                % (
                    repository["full_name"],
                    _format_bytes(size) if size is not None else "size unavailable",
                    repository["active_candidate_count"],
                )
            )
        query_outliers = document["outliers"]["observed_queries"]
        if query_outliers:
            for query in query_outliers[:3]:
                print(
                    "  query outlier: %s/%s %s (%d observed candidates)"
                    % (
                        query["source"],
                        query["library_id"],
                        query["signal"] or query["query_fingerprint"][:12],
                        query["observed_active_candidates"],
                    )
                )
        else:
            for group in document["outliers"]["planned_query_groups"][:3]:
                print(
                    "  planned query outlier: %s (%d declared signals)"
                    % (
                        group["library_id"],
                        group["declared_signal_queries"],
                    )
                )
        if plan.requires_full_confirmation:
            if args.mode == "refresh":
                print("  decision: weekly refresh refused; attended reconciliation required")
            else:
                print("  decision: explicit --confirm-full required to reconcile")
        for reason in plan.reasons:
            print("  reason: %s" % reason)
    return 0


def _run(args, mode):
    budgets = _budget(args, mode)
    pipeline = CollectorPipeline.production(
        repo_root=args.repo_root,
        state_path=args.state,
        cache_root=args.cache,
        data_dir=args.data,
        budgets=budgets,
        mode=mode,
    )
    caffeinate = None
    if mode == "reconcile" and shutil.which("caffeinate"):
        # The helper exits with this coordinator PID; it cannot outlive the run.
        caffeinate = subprocess.Popen(
            ["caffeinate", "-dimsu", "-w", str(__import__("os").getpid())],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    try:
        result = pipeline.run(
            mode=mode,
            confirm_full=bool(getattr(args, "confirm_full", False)),
            library_ids=_libraries(getattr(args, "libraries", ())),
            budgets=budgets,
        )
    finally:
        if caffeinate is not None and caffeinate.poll() is None:
            caffeinate.terminate()
    print(json.dumps({
        "run_id": result["run_id"],
        "release_id": result["release_id"],
        "scanned": result["scanned"],
        "manifest": str(
            (Path(args.repo_root).resolve() / args.data / "v2" / "manifest.json")
            .resolve()
        ),
        "report": result["report"],
        "launchd_armed": False,
    }, indent=2))
    return 0


def _run_phase8_cohort(args):
    if not args.confirm_cohort:
        raise PipelineError(
            "cohort-reconcile requires --confirm-cohort after reviewing "
            "the seeded successor and preflight"
        )
    root = Path(args.repo_root).resolve()
    with StateDB(root / args.state) as state:
        row = state.connection.execute(
            """
            SELECT mode, plan_json, budgets_json, status
            FROM runs WHERE run_id=?
            """,
            (args.successor_run_id,),
        ).fetchone()
        if row is None:
            raise PipelineError("cohort successor run does not exist")
        try:
            plan = json.loads(row["plan_json"] or "{}")
            contract = dict(plan["execution_contract"])
            budgets = RunBudgets(**json.loads(row["budgets_json"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "cohort successor execution contract is malformed"
            ) from exc
    baseline_budgets = RunBudgets.reconcile().to_dict()
    actual_budgets = budgets.to_dict()
    extension = contract.get("wall_extension")
    unchanged_actual = dict(actual_budgets)
    unchanged_actual.pop("max_wall_seconds", None)
    unchanged_baseline = dict(baseline_budgets)
    unchanged_baseline.pop("max_wall_seconds", None)
    wall_contract_valid = (
        actual_budgets == baseline_budgets
        if extension is None
        else (
            isinstance(extension, dict)
            and extension.get("extended_limit_seconds")
            == actual_budgets.get("max_wall_seconds")
            and unchanged_actual == unchanged_baseline
        )
    )
    if (
        row["mode"] != "reconcile"
        or row["status"] not in {"running", "failed"}
        or contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or not wall_contract_valid
    ):
        raise PipelineError(
            "run is not a resumable reviewed Phase 8 cohort successor"
        )
    selected = tuple(contract.get("selected_library_ids") or ())
    if not selected:
        raise PipelineError("cohort successor has no selected libraries")
    pipeline = CollectorPipeline.production(
        repo_root=root,
        state_path=args.state,
        cache_root=args.cache,
        data_dir=args.data,
        budgets=budgets,
        mode="reconcile",
        metadata_batch_size=int(contract["metadata_batch_size"]),
    )
    caffeinate = None
    if shutil.which("caffeinate"):
        caffeinate = subprocess.Popen(
            ["caffeinate", "-dimsu", "-w", str(os.getpid())],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    try:
        result = pipeline.run(
            mode="reconcile",
            confirm_full=True,
            library_ids=selected,
            budgets=budgets,
            reviewed_execution_contract=contract,
        )
    finally:
        if caffeinate is not None and caffeinate.poll() is None:
            caffeinate.terminate()
    print(json.dumps({
        "run_id": result["run_id"],
        "release_id": result["release_id"],
        "run_class": contract["run_class"],
        "release_scope": contract["release_scope"],
        "selected_library_count": len(selected),
        "scanned": result["scanned"],
        "manifest": str(
            (
                root
                / args.data
                / "v2"
                / "manifest.json"
            ).resolve()
        ),
        "report": result["report"],
        "launchd_armed": False,
    }, indent=2))
    return 0


def _extend_phase8_wall(args):
    if not args.confirm:
        raise PipelineError(
            "run-wall-extend requires --confirm after reviewing the wall-only change"
        )
    from .phase8_control import authorize_phase8_wall_extension

    root = Path(args.repo_root).resolve()
    owner = "cli-wall-extension:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError(
                "the active collector must finish or stop before wall extension is applied"
            )
        try:
            result = authorize_phase8_wall_extension(
                state=state,
                repo_root=root,
                cache_root=root / args.cache,
                run_id=args.run_id,
                predecessor_source_ref=args.predecessor_source_ref,
                extended_limit_seconds=int(args.max_wall_hours) * 3600,
                reason=args.reason,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _retry_phase8_issues(args):
    if not args.confirm:
        raise PipelineError(
            "run-issue-retry requires --confirm after reviewing the "
            "typed failure ledger"
        )
    from .phase8_control import authorize_phase8_issue_retry

    root = Path(args.repo_root).resolve()
    owner = "cli-issue-retry:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError(
                "the active collector must finish or stop before issue retry"
            )
        try:
            result = authorize_phase8_issue_retry(
                state=state,
                run_id=args.run_id,
                reason=args.reason,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _migrate_phase8_scanner_source(args):
    if not args.confirm:
        raise PipelineError(
            "run-scanner-source-migrate requires --confirm after reviewing "
            "the exact issue-lane source and compatibility proof"
        )
    from .phase8_source_migration import (
        authorize_phase8_scanner_source_migration,
    )

    root = Path(args.repo_root).resolve()
    owner = "cli-scanner-source-migrate:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before scanner migration"
            )
        try:
            result = authorize_phase8_scanner_source_migration(
                state=state,
                repo_root=root,
                run_id=args.run_id,
                reason=args.reason,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _retry_phase8_scanner_source_issues(args):
    if not args.confirm:
        raise PipelineError(
            "run-scanner-source-issues requires --confirm after reviewing "
            "the exact four-incident source-migration proof"
        )
    from .phase8_source_migration import (
        authorize_phase8_scanner_source_issue_retry,
    )

    root = Path(args.repo_root).resolve()
    owner = "cli-scanner-source-issues:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError(
                "the active collector must finish or stop before scanner "
                "source issue retry"
            )
        try:
            result = authorize_phase8_scanner_source_issue_retry(
                state=state,
                repo_root=root,
                run_id=args.run_id,
                reason=args.reason,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_scanner_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-scanner-resume-control requires --confirm after reviewing "
            "the exact source-only compatibility proof"
        )
    from .phase8_resume_control import (
        authorize_phase8_scanner_resume_control,
    )

    root = Path(args.repo_root).resolve()
    owner = "cli-scanner-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before scanner "
                "resume control"
            )
        try:
            result = authorize_phase8_scanner_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
                reason=args.reason,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _defer_phase8_scan_tail(args):
    if not args.confirm:
        raise PipelineError(
            "run-scan-tail-stop requires --confirm after reviewing the "
            "exact owner-authorized deferred repository set"
        )
    from .phase8_tail_control import authorize_phase8_scan_tail_deferral

    root = Path(args.repo_root).resolve()
    owner = "cli-scan-tail-stop:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before scan-tail "
                "deferral"
            )
        try:
            result = authorize_phase8_scan_tail_deferral(
                state=state,
                repo_root=root,
                run_id=args.run_id,
                reason=args.reason,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_scan_tail_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-scan-tail-resume-control requires --confirm after reviewing "
            "the exact whole-repository quarantine compatibility proof"
        )
    from .phase8_tail_control import (
        authorize_phase8_scan_tail_resume_control,
    )

    root = Path(args.repo_root).resolve()
    owner = "cli-scan-tail-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before scan-tail "
                "resume control"
            )
        try:
            result = authorize_phase8_scan_tail_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_downstream_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-downstream-resume-control requires --confirm after reviewing "
            "the exact post-OpenAlex staging correction"
        )
    from .phase8_tail_control import (
        authorize_phase8_downstream_resume_control,
    )

    root = Path(args.repo_root).resolve()
    owner = "cli-downstream-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before downstream "
                "resume control"
            )
        try:
            result = authorize_phase8_downstream_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
                repair_state_path=(
                    Path(args.repair_state).resolve()
                    if args.repair_state
                    else None
                ),
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_visibility_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-visibility-resume-control requires --confirm after "
            "reviewing the exact sanitized missing-node proof"
        )
    from .phase8_tail_control import (
        authorize_phase8_visibility_resume_control,
    )

    root = Path(args.repo_root).resolve()
    owner = "cli-visibility-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before visibility "
                "resume control"
            )
        try:
            result = authorize_phase8_visibility_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_graphql_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-graphql-resume-control requires --confirm after reviewing "
            "the exact embedded-usage and partial-epoch proof"
        )
    from .phase8_tail_control import authorize_phase8_graphql_resume_control

    root = Path(args.repo_root).resolve()
    owner = "cli-graphql-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before GraphQL "
                "resume control"
            )
        try:
            result = authorize_phase8_graphql_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_privacy_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-privacy-resume-control requires --confirm after reviewing "
            "the exact privacy-purge and scan-pin proof"
        )
    from .phase8_tail_control import authorize_phase8_privacy_resume_control
    root = Path(args.repo_root).resolve()
    reference = Path(args.reference_state)
    if not reference.is_absolute():
        reference = root / reference
    owner = "cli-privacy-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before privacy resume"
            )
        try:
            result = authorize_phase8_privacy_resume_control(
                state=state, repo_root=root, run_id=args.run_id,
                reference_state_path=reference.resolve(),
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_fresh_candidate_deferral(args):
    if not args.confirm:
        raise PipelineError(
            "run-fresh-candidate-deferral-control requires --confirm after "
            "reviewing the exact unscanned post-refresh candidate proof"
        )
    from .phase8_tail_control import (
        authorize_phase8_fresh_candidate_deferral_control,
    )
    root = Path(args.repo_root).resolve()
    proof = Path(args.proof_file)
    if not proof.is_absolute():
        proof = root / proof
    owner = "cli-fresh-candidate-deferral-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "fresh-candidate deferral control"
            )
        try:
            result = authorize_phase8_fresh_candidate_deferral_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
                proof_path=proof.resolve(),
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_visibility_set_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-visibility-set-resume-control requires --confirm after "
            "reviewing the exact failed-epoch proof"
        )
    from .phase8_tail_control import (
        authorize_phase8_visibility_set_resume_control,
    )
    root = Path(args.repo_root).resolve()
    owner = "cli-visibility-set-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "visibility-set resume control"
            )
        try:
            result = authorize_phase8_visibility_set_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_visibility_rejection_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-visibility-rejection-resume-control requires --confirm "
            "after reviewing the exact newest-epoch missing-node proof"
        )
    from .phase8_tail_control import (
        authorize_phase8_visibility_rejection_resume_control,
    )
    root = Path(args.repo_root).resolve()
    owner = "cli-visibility-rejection-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "visibility-rejection resume control"
            )
        try:
            result = authorize_phase8_visibility_rejection_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_visibility_refresh_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-visibility-refresh-resume-control requires --confirm "
            "after reviewing the exact prior-epoch collision proof"
        )
    from .phase8_tail_control import (
        authorize_phase8_visibility_refresh_resume_control,
    )
    root = Path(args.repo_root).resolve()
    owner = "cli-visibility-refresh-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "visibility-refresh resume control"
            )
        try:
            result = authorize_phase8_visibility_refresh_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_visibility_budget_resume(args):
    if not args.confirm:
        raise PipelineError(
            "run-visibility-budget-resume-control requires --confirm "
            "after reviewing the unchanged-budget batch plan"
        )
    from .phase8_tail_control import (
        authorize_phase8_visibility_budget_resume_control,
    )
    root = Path(args.repo_root).resolve()
    owner = "cli-visibility-budget-resume-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "visibility-budget resume control"
            )
        try:
            result = authorize_phase8_visibility_budget_resume_control(
                state=state,
                repo_root=root,
                run_id=args.run_id,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_visibility_transport_retry(args):
    if not args.confirm:
        raise PipelineError(
            "run-visibility-transport-retry-control requires --confirm "
            "after reviewing the single malformed-response reserve"
        )
    from .phase8_tail_control import (
        authorize_phase8_visibility_transport_retry_control,
    )
    root = Path(args.repo_root).resolve()
    owner = "cli-visibility-transport-retry-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "visibility transport retry control"
            )
        try:
            result = authorize_phase8_visibility_transport_retry_control(
                state=state, repo_root=root, run_id=args.run_id
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_visibility_epoch_recovery(args):
    if not args.confirm:
        raise PipelineError(
            "run-visibility-epoch-recovery-control requires --confirm "
            "after reviewing the exact task restoration"
        )
    from .phase8_tail_control import (
        authorize_phase8_visibility_epoch_recovery_control,
    )
    root = Path(args.repo_root).resolve()
    owner = "cli-visibility-epoch-recovery-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "visibility epoch recovery control"
            )
        try:
            result = authorize_phase8_visibility_epoch_recovery_control(
                state=state, repo_root=root, run_id=args.run_id,
                reference_state_path=Path(args.reference_state),
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_post_refresh_privacy(args):
    if not args.confirm:
        raise PipelineError(
            "run-post-refresh-privacy-control requires --confirm after "
            "reviewing the exact additional privacy purge"
        )
    from .phase8_tail_control import (
        authorize_phase8_post_refresh_privacy_control,
    )
    root = Path(args.repo_root).resolve()
    owner = "cli-post-refresh-privacy-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "post-refresh privacy control"
            )
        try:
            result = authorize_phase8_post_refresh_privacy_control(
                state=state, repo_root=root, run_id=args.run_id,
                reference_state_path=Path(args.reference_state),
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _authorize_phase8_final_visibility_privacy(args):
    if not args.confirm:
        raise PipelineError(
            "run-final-visibility-privacy-control requires --confirm after "
            "reviewing the exact missing-node purge"
        )
    from .phase8_tail_control import (
        authorize_phase8_final_visibility_privacy_control,
    )
    root = Path(args.repo_root).resolve()
    owner = "cli-final-visibility-privacy-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before "
                "final-visibility privacy control"
            )
        try:
            result = authorize_phase8_final_visibility_privacy_control(
                state=state, repo_root=root, run_id=args.run_id,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _retry_phase8_buildozer_issue(args):
    if not args.confirm:
        raise PipelineError(
            "run-buildozer-issue requires --confirm after reviewing the "
            "exact generated-directory proof"
        )
    from .phase8_control import authorize_phase8_buildozer_retry

    root = Path(args.repo_root).resolve()
    owner = "cli-buildozer-issue:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError(
                "the active collector must finish or stop before buildozer retry"
            )
        try:
            result = authorize_phase8_buildozer_retry(
                state=state,
                run_id=args.run_id,
                reason=args.reason,
            )
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _run_phase8_certified_issues(args, *, kind):
    from .phase8_issue_lane import (
        run_blocked_lfs_inspection_issue_lane,
        run_notebook_issue_lane,
    )

    lanes = {
        "notebook": (
            "run-notebook-issues",
            "frozen exact-blob proof",
            run_notebook_issue_lane,
        ),
        "lfs-inspection": (
            "run-lfs-inspection-issues",
            "exact local-Git-blob proof",
            run_blocked_lfs_inspection_issue_lane,
        ),
    }
    try:
        command, proof_label, runner = lanes[kind]
    except KeyError as exc:
        raise PipelineError("unknown certified issue lane") from exc
    if not args.confirm:
        raise PipelineError(
            "%s requires --confirm after reviewing the %s"
            % (command, proof_label)
        )
    root = Path(args.repo_root).resolve()
    owner = "cli-%s:%d" % (kind, os.getpid())
    caffeinate = None
    lock_heartbeat = None
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=900
        ):
            raise PipelineError(
                "the active collector must finish or stop before " + kind
            )
        try:
            lock_heartbeat = _RunLockHeartbeat(
                root / args.state,
                "collector-network-run",
                owner,
                900,
            )
            lock_heartbeat.start()
            if shutil.which("caffeinate"):
                caffeinate = subprocess.Popen(
                    ["caffeinate", "-dimsu", "-w", str(os.getpid())],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            result = runner(
                state=state,
                repo_root=root,
                state_path=args.state,
                cache_root=args.cache,
                data_dir=args.data,
                run_id=args.run_id,
            )
            lock_heartbeat.verify(state)
        finally:
            if caffeinate is not None and caffeinate.poll() is None:
                caffeinate.terminate()
            if lock_heartbeat is not None:
                lock_heartbeat.stop()
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _run_phase8_notebook_issues(args):
    return _run_phase8_certified_issues(args, kind="notebook")


def _run_phase8_lfs_inspection_issues(args):
    return _run_phase8_certified_issues(args, kind="lfs-inspection")


def _compare(args):
    """Run deterministic fixture comparisons only; never touches production data."""
    if args.repositories:
        raise PipelineError(
            "named network comparison is intentionally not implicit; use fixture "
            "comparison or the attended reconcile planner"
        )
    command = [
        sys.executable,
        "-m",
        "unittest",
        "-v",
        "test_req14_scanner.py",
        "test_req14_portfolio.py",
    ]
    # Scanner fixtures deliberately exercise process-group cancellation. Keep
    # that test tree out of the interactive shell/CI wrapper's process group
    # so a cleanup signal can never terminate the caller. If the wrapper is
    # interrupted, explicitly reap the isolated unittest process tree.
    process = subprocess.Popen(
        command,
        cwd=args.repo_root,
        start_new_session=True,
    )
    try:
        return process.wait()
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            process.wait()
        raise


def _validate(args):
    errors = validate_v2(
        (Path(args.repo_root).resolve() / args.data / "v2").resolve()
    )
    if errors:
        for error in errors:
            print("ERROR: " + error, file=sys.stderr)
        return 1
    print("V2 release validation passed")
    return 0


def _run_control(args, action):
    if not args.confirm:
        raise PipelineError(
            "%s requires --confirm after reviewing the interrupted run"
            % action
        )
    root = Path(args.repo_root).resolve()
    owner = "cli-control:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError("another collector run owns the state lock")
        try:
            try:
                if action == "abandon":
                    state.abandon_run(args.run_id, reason=args.reason)
                    changed = None
                else:
                    changed = state.reset_failed_tasks(
                        args.run_id, reason=args.reason
                    )
            except (KeyError, RuntimeError, ValueError) as exc:
                raise PipelineError(str(exc)) from exc
        finally:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps({
        "action": action,
        "run_id": args.run_id,
        "reset_tasks": changed,
    }, indent=2))
    return 0


def _prepare_successor(args):
    if not args.confirm:
        raise PipelineError(
            "run-successor requires --confirm after reviewing the scope reduction"
        )
    from .successor import prepare_scope_reduction_successor

    root = Path(args.repo_root).resolve()
    owner = "cli-successor:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError("another collector run owns the state lock")
    try:
        report = prepare_scope_reduction_successor(
            repo_root=root,
            state_path=args.state,
            data_dir=args.data,
            predecessor_run_id=args.predecessor_run_id,
            allowed_library_id=args.scope_reduction_library,
            reason=args.reason,
            budgets=_budget(args, "reconcile"),
        )
    except (KeyError, RuntimeError, ValueError) as exc:
        raise PipelineError(str(exc)) from exc
    finally:
        with StateDB(root / args.state) as state:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _prepare_transport_successor(args):
    if not args.confirm:
        raise PipelineError(
            "run-transport-successor requires --confirm after reviewing "
            "the network-execution remediation"
        )
    from .successor import prepare_transport_policy_successor

    root = Path(args.repo_root).resolve()
    owner = "cli-transport-successor:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError("another collector run owns the state lock")
    try:
        report = prepare_transport_policy_successor(
            repo_root=root,
            state_path=args.state,
            data_dir=args.data,
            predecessor_run_id=args.predecessor_run_id,
            predecessor_source_ref=args.predecessor_source_ref,
            reason=args.reason,
            historical_github_request_attempts=(
                args.historical_github_request_attempts
            ),
            budgets=_budget(args, "reconcile"),
        )
    except (KeyError, RuntimeError, ValueError) as exc:
        raise PipelineError(str(exc)) from exc
    finally:
        with StateDB(root / args.state) as state:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _prepare_phase8_cohort_successor(args):
    if not args.confirm:
        raise PipelineError(
            "run-cohort-successor requires --confirm after reviewing "
            "the product-boundary stop"
        )
    from .successor import prepare_phase8_cohort_successor

    root = Path(args.repo_root).resolve()
    owner = "cli-cohort-successor:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError("another collector run owns the state lock")
    try:
        report = prepare_phase8_cohort_successor(
            repo_root=root,
            state_path=args.state,
            data_dir=args.data,
            predecessor_run_id=args.predecessor_run_id,
            predecessor_source_ref=args.predecessor_source_ref,
            reason=args.reason,
            budgets=RunBudgets.reconcile(),
        )
    except (KeyError, RuntimeError, ValueError) as exc:
        raise PipelineError(str(exc)) from exc
    finally:
        with StateDB(root / args.state) as state:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _prepare_phase8_cohort_recovery_successor(args):
    if not args.confirm:
        raise PipelineError(
            "run-cohort-recovery-successor requires --confirm after "
            "reviewing the identity/scan remediation"
        )
    from .successor import prepare_phase8_cohort_successor

    root = Path(args.repo_root).resolve()
    owner = "cli-cohort-recovery-successor:%d" % os.getpid()
    with StateDB(root / args.state) as state:
        if not state.acquire_lock(
            "collector-network-run", owner=owner, lease_seconds=300
        ):
            raise PipelineError("another collector run owns the state lock")
    try:
        report = prepare_phase8_cohort_successor(
            repo_root=root,
            state_path=args.state,
            data_dir=args.data,
            predecessor_run_id=args.predecessor_run_id,
            predecessor_source_ref=args.predecessor_source_ref,
            reason=args.reason,
            budgets=RunBudgets.reconcile(),
            recovery_remediation=True,
            control_plane_remediation=bool(
                args.control_plane_remediation
            ),
            scan_runtime_remediation=bool(
                args.scan_runtime_remediation
            ),
            candidate_policy_remediation=bool(
                args.candidate_policy_remediation
            ),
            preflight_reuse_remediation=bool(
                args.preflight_reuse_remediation
            ),
            preflight_budget_remediation=bool(
                args.preflight_budget_remediation
            ),
            checkpoint_continuation_remediation=bool(
                args.checkpoint_continuation_remediation
            ),
        )
    except (KeyError, RuntimeError, ValueError) as exc:
        raise PipelineError(str(exc)) from exc
    finally:
        with StateDB(root / args.state) as state:
            state.release_lock("collector-network-run", owner=owner)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Stateful Mac-local CUDA-X collector (REQ-14)"
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--state", default=".state/collector.sqlite3")
    parser.add_argument("--cache", default=".state/git-cache")
    parser.add_argument("--data", default="data")
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="read-only local work and budget plan")
    plan.add_argument("--mode", choices=("refresh", "reconcile"), default="refresh")
    plan.add_argument("--weekly-scan-budget", type=int)
    _add_budget_flags(plan)
    plan.add_argument("--json", action="store_true")
    plan.set_defaults(handler=_plan)

    refresh = sub.add_parser("refresh", help="bounded weekly incremental")
    _add_budget_flags(refresh)
    refresh.set_defaults(handler=lambda args: _run(args, "refresh"))

    reconcile = sub.add_parser(
        "reconcile", help="attended complete all-library reconciliation"
    )
    reconcile.add_argument("--confirm-full", action="store_true")
    _add_budget_flags(reconcile)
    reconcile.set_defaults(handler=lambda args: _run(args, "reconcile"))

    onboard = sub.add_parser(
        "onboard", help="targeted libraries through the shared state engine"
    )
    onboard.add_argument("--libraries", nargs="+", required=True)
    _add_budget_flags(onboard)
    onboard.set_defaults(handler=lambda args: _run(args, "onboard"))

    cohort = sub.add_parser(
        "cohort-reconcile",
        help="resume the reviewed 36-hour Phase 8 partial cohort successor",
    )
    cohort.add_argument("--successor-run-id", required=True)
    cohort.add_argument("--confirm-cohort", action="store_true")
    cohort.set_defaults(handler=_run_phase8_cohort)

    compare = sub.add_parser(
        "compare", help="bounded old/new detector fixture comparison"
    )
    compare.add_argument("--repositories", nargs="*", default=())
    compare.set_defaults(handler=_compare)

    validate = sub.add_parser("validate", help="validate current V2 release")
    validate.set_defaults(handler=_validate)

    abandon = sub.add_parser(
        "run-abandon",
        help="explicitly abandon a reviewed interrupted run",
    )
    abandon.add_argument("--run-id", required=True)
    abandon.add_argument("--reason", default="owner_review")
    abandon.add_argument("--confirm", action="store_true")
    abandon.set_defaults(handler=lambda args: _run_control(args, "abandon"))

    retry = sub.add_parser(
        "run-retry",
        help="reset exhausted tasks after reviewed remediation",
    )
    retry.add_argument("--run-id", required=True)
    retry.add_argument("--reason", default="owner_review")
    retry.add_argument("--confirm", action="store_true")
    retry.set_defaults(handler=lambda args: _run_control(args, "retry"))

    wall_extend = sub.add_parser(
        "run-wall-extend",
        help="extend only the reviewed Phase 8 overall wall ceiling",
    )
    wall_extend.add_argument("--run-id", required=True)
    wall_extend.add_argument("--predecessor-source-ref", required=True)
    wall_extend.add_argument(
        "--max-wall-hours", type=int, default=168
    )
    wall_extend.add_argument(
        "--reason", default="phase8_owner_wall_extension"
    )
    wall_extend.add_argument("--confirm", action="store_true")
    wall_extend.set_defaults(handler=_extend_phase8_wall)

    issue_retry = sub.add_parser(
        "run-issue-retry",
        help="requeue only fully-accounted Phase 8 transient scan incidents",
    )
    issue_retry.add_argument("--run-id", required=True)
    issue_retry.add_argument(
        "--reason", default="phase8_typed_transient_retry"
    )
    issue_retry.add_argument("--confirm", action="store_true")
    issue_retry.set_defaults(handler=_retry_phase8_issues)

    scanner_migrate = sub.add_parser(
        "run-scanner-source-migrate",
        help="adopt the exact audited Phase 8 scanner issue lane",
    )
    scanner_migrate.add_argument("--run-id", required=True)
    scanner_migrate.add_argument(
        "--reason", default="phase8_audited_scanner_source_migration"
    )
    scanner_migrate.add_argument("--confirm", action="store_true")
    scanner_migrate.set_defaults(handler=_migrate_phase8_scanner_source)

    scanner_source_issues = sub.add_parser(
        "run-scanner-source-issues",
        help="retry only incidents fixed by the audited scanner source lane",
    )
    scanner_source_issues.add_argument("--run-id", required=True)
    scanner_source_issues.add_argument(
        "--reason", default="phase8_audited_scanner_source_issue_retry"
    )
    scanner_source_issues.add_argument("--confirm", action="store_true")
    scanner_source_issues.set_defaults(
        handler=_retry_phase8_scanner_source_issues
    )

    scanner_resume_control = sub.add_parser(
        "run-scanner-resume-control",
        help="adopt the audited Phase 8 scanner orchestration source",
    )
    scanner_resume_control.add_argument("--run-id", required=True)
    scanner_resume_control.add_argument(
        "--reason", default="phase8_audited_scanner_resume_control"
    )
    scanner_resume_control.add_argument("--confirm", action="store_true")
    scanner_resume_control.set_defaults(
        handler=_authorize_phase8_scanner_resume
    )

    scan_tail_stop = sub.add_parser(
        "run-scan-tail-stop",
        help="defer the exact unresolved Phase 8 scan tail and continue",
    )
    scan_tail_stop.add_argument("--run-id", required=True)
    scan_tail_stop.add_argument(
        "--reason", default="phase8_owner_deferred_scan_retry_tail"
    )
    scan_tail_stop.add_argument("--confirm", action="store_true")
    scan_tail_stop.set_defaults(handler=_defer_phase8_scan_tail)

    scan_tail_resume = sub.add_parser(
        "run-scan-tail-resume-control",
        help="adopt the exact whole-repository tail quarantine correction",
    )
    scan_tail_resume.add_argument("--run-id", required=True)
    scan_tail_resume.add_argument("--confirm", action="store_true")
    scan_tail_resume.set_defaults(
        handler=_authorize_phase8_scan_tail_resume
    )

    downstream_resume = sub.add_parser(
        "run-downstream-resume-control",
        help="adopt the exact post-OpenAlex staging correction",
    )
    downstream_resume.add_argument("--run-id", required=True)
    downstream_resume.add_argument(
        "--repair-state",
        help=(
            "read-only pre-supersession SQLite state used only when the "
            "certified deferred rows require exact repair"
        ),
    )
    downstream_resume.add_argument("--confirm", action="store_true")
    downstream_resume.set_defaults(
        handler=_authorize_phase8_downstream_resume
    )

    visibility_resume = sub.add_parser(
        "run-visibility-resume-control",
        help="adopt the exact missing-node fresh-metadata correction",
    )
    visibility_resume.add_argument("--run-id", required=True)
    visibility_resume.add_argument("--confirm", action="store_true")
    visibility_resume.set_defaults(
        handler=_authorize_phase8_visibility_resume
    )

    graphql_resume = sub.add_parser(
        "run-graphql-resume-control",
        help="resume the exact partial fresh metadata epoch",
    )
    graphql_resume.add_argument("--run-id", required=True)
    graphql_resume.add_argument("--confirm", action="store_true")
    graphql_resume.set_defaults(handler=_authorize_phase8_graphql_resume)

    privacy_resume = sub.add_parser(
        "run-privacy-resume-control",
        help="reconcile exact fresh-metadata privacy removals",
    )
    privacy_resume.add_argument("--run-id", required=True)
    privacy_resume.add_argument("--reference-state", required=True)
    privacy_resume.add_argument("--confirm", action="store_true")
    privacy_resume.set_defaults(handler=_authorize_phase8_privacy_resume)

    fresh_candidate_deferral = sub.add_parser(
        "run-fresh-candidate-deferral-control",
        help="defer exact post-refresh candidates outside the scan universe",
    )
    fresh_candidate_deferral.add_argument("--run-id", required=True)
    fresh_candidate_deferral.add_argument("--proof-file", required=True)
    fresh_candidate_deferral.add_argument("--confirm", action="store_true")
    fresh_candidate_deferral.set_defaults(
        handler=_authorize_phase8_fresh_candidate_deferral
    )

    visibility_set_resume = sub.add_parser(
        "run-visibility-set-resume-control",
        help="supersede an incompatible failed final-visibility epoch",
    )
    visibility_set_resume.add_argument("--run-id", required=True)
    visibility_set_resume.add_argument("--confirm", action="store_true")
    visibility_set_resume.set_defaults(
        handler=_authorize_phase8_visibility_set_resume
    )

    visibility_rejection_resume = sub.add_parser(
        "run-visibility-rejection-resume-control",
        help=(
            "refresh metadata after an exact missing node in the newest "
            "final-visibility epoch"
        ),
    )
    visibility_rejection_resume.add_argument("--run-id", required=True)
    visibility_rejection_resume.add_argument(
        "--confirm", action="store_true"
    )
    visibility_rejection_resume.set_defaults(
        handler=_authorize_phase8_visibility_rejection_resume
    )

    visibility_refresh_resume = sub.add_parser(
        "run-visibility-refresh-resume-control",
        help=(
            "start a new fresh metadata epoch after an exact prior-epoch "
            "collision"
        ),
    )
    visibility_refresh_resume.add_argument("--run-id", required=True)
    visibility_refresh_resume.add_argument("--confirm", action="store_true")
    visibility_refresh_resume.set_defaults(
        handler=_authorize_phase8_visibility_refresh_resume
    )

    visibility_budget_resume = sub.add_parser(
        "run-visibility-budget-resume-control",
        help=(
            "use reviewed 100-lookup metadata batches without changing "
            "the GraphQL budget"
        ),
    )
    visibility_budget_resume.add_argument("--run-id", required=True)
    visibility_budget_resume.add_argument("--confirm", action="store_true")
    visibility_budget_resume.set_defaults(
        handler=_authorize_phase8_visibility_budget_resume
    )

    visibility_transport_retry = sub.add_parser(
        "run-visibility-transport-retry-control",
        help=(
            "reserve one point before retrying the exact malformed "
            "GraphQL response"
        ),
    )
    visibility_transport_retry.add_argument("--run-id", required=True)
    visibility_transport_retry.add_argument("--confirm", action="store_true")
    visibility_transport_retry.set_defaults(
        handler=_authorize_phase8_visibility_transport_retry
    )

    visibility_epoch_recovery = sub.add_parser(
        "run-visibility-epoch-recovery-control",
        help="restore and resume the exact superseded metadata epoch",
    )
    visibility_epoch_recovery.add_argument("--run-id", required=True)
    visibility_epoch_recovery.add_argument(
        "--reference-state", required=True
    )
    visibility_epoch_recovery.add_argument("--confirm", action="store_true")
    visibility_epoch_recovery.set_defaults(
        handler=_authorize_phase8_visibility_epoch_recovery
    )

    post_refresh_privacy = sub.add_parser(
        "run-post-refresh-privacy-control",
        help="certify the exact additional nonpublic refresh purge",
    )
    post_refresh_privacy.add_argument("--run-id", required=True)
    post_refresh_privacy.add_argument(
        "--reference-state", required=True
    )
    post_refresh_privacy.add_argument("--confirm", action="store_true")
    post_refresh_privacy.set_defaults(
        handler=_authorize_phase8_post_refresh_privacy
    )

    final_visibility_privacy = sub.add_parser(
        "run-final-visibility-privacy-control",
        help=(
            "purge an exact newly missing final-visibility repository and "
            "resume its compatible epoch"
        ),
    )
    final_visibility_privacy.add_argument("--run-id", required=True)
    final_visibility_privacy.add_argument("--confirm", action="store_true")
    final_visibility_privacy.set_defaults(
        handler=_authorize_phase8_final_visibility_privacy
    )

    buildozer_issue = sub.add_parser(
        "run-buildozer-issue",
        help="retry only the certified shootAnalyzer .buildozer incident",
    )
    buildozer_issue.add_argument("--run-id", required=True)
    buildozer_issue.add_argument(
        "--reason", default="phase8_approved_buildozer_exclusion"
    )
    buildozer_issue.add_argument("--confirm", action="store_true")
    buildozer_issue.set_defaults(handler=_retry_phase8_buildozer_issue)

    notebook_issues = sub.add_parser(
        "run-notebook-issues",
        help="certify and retry exact Phase 8 malformed-notebook incidents",
    )
    notebook_issues.add_argument("--run-id", required=True)
    notebook_issues.add_argument("--confirm", action="store_true")
    notebook_issues.set_defaults(handler=_run_phase8_notebook_issues)

    lfs_issues = sub.add_parser(
        "run-lfs-inspection-issues",
        help="certify and retry exact macOS-denied LFS precheck reads",
    )
    lfs_issues.add_argument("--run-id", required=True)
    lfs_issues.add_argument("--confirm", action="store_true")
    lfs_issues.set_defaults(handler=_run_phase8_lfs_inspection_issues)

    successor = sub.add_parser(
        "run-successor",
        help="prepare an audited discovery scope-reduction successor",
    )
    successor.add_argument("--predecessor-run-id", required=True)
    successor.add_argument("--scope-reduction-library", required=True)
    successor.add_argument(
        "--reason", default="reviewed_discovery_scope_reduction"
    )
    successor.add_argument("--confirm", action="store_true")
    _add_budget_flags(successor)
    successor.set_defaults(handler=_prepare_successor)

    transport_successor = sub.add_parser(
        "run-transport-successor",
        help="prepare an audited successor after network-execution remediation",
    )
    transport_successor.add_argument("--predecessor-run-id", required=True)
    transport_successor.add_argument("--predecessor-source-ref", required=True)
    transport_successor.add_argument(
        "--historical-github-request-attempts",
        type=int,
        required=True,
    )
    transport_successor.add_argument(
        "--reason", default="reviewed_transport_policy_remediation"
    )
    transport_successor.add_argument("--confirm", action="store_true")
    _add_budget_flags(transport_successor)
    transport_successor.set_defaults(
        handler=_prepare_transport_successor
    )

    cohort_successor = sub.add_parser(
        "run-cohort-successor",
        help="derive and seed an audited Phase 8 partial-cohort successor",
    )
    cohort_successor.add_argument("--predecessor-run-id", required=True)
    cohort_successor.add_argument("--predecessor-source-ref", required=True)
    cohort_successor.add_argument(
        "--reason", default="phase8_cohort_a_product_boundary"
    )
    cohort_successor.add_argument("--confirm", action="store_true")
    cohort_successor.set_defaults(
        handler=_prepare_phase8_cohort_successor
    )
    cohort_recovery = sub.add_parser(
        "run-cohort-recovery-successor",
        help=(
            "seed an audited Phase 8 successor after candidate-identity "
            "and scan-runtime remediation"
        ),
    )
    cohort_recovery.add_argument(
        "--predecessor-run-id", required=True
    )
    cohort_recovery.add_argument(
        "--predecessor-source-ref", required=True
    )
    cohort_recovery.add_argument(
        "--reason",
        default="phase8_cohort_identity_scan_remediation",
    )
    cohort_recovery.add_argument(
        "--control-plane-remediation",
        action="store_true",
        help=(
            "derive an import-only chained successor after the reviewed "
            "preseed-contract validator failed before scan work"
        ),
    )
    cohort_recovery.add_argument(
        "--scan-runtime-remediation",
        action="store_true",
        help=(
            "derive a chained successor after reviewed scanner-runtime "
            "remediation and invalidate affected predecessor scans"
        ),
    )
    cohort_recovery.add_argument(
        "--candidate-policy-remediation",
        action="store_true",
        help=(
            "derive a chained successor after an exact reviewed "
            "candidate-evidence policy reduction"
        ),
    )
    cohort_recovery.add_argument(
        "--preflight-reuse-remediation",
        action="store_true",
        help=(
            "derive a no-network chained successor after the reviewed "
            "effective-detector preflight reuse correction"
        ),
    )
    cohort_recovery.add_argument(
        "--preflight-budget-remediation",
        action="store_true",
        help=(
            "derive a no-network chained successor after the reviewed "
            "lineage scan-budget preflight correction"
        ),
    )
    cohort_recovery.add_argument(
        "--checkpoint-continuation-remediation",
        action="store_true",
        help=(
            "continue the owner-reviewed Phase 8 checkpoint, preserve "
            "compatible completed scans, and retain interrupted usage as "
            "unknown"
        ),
    )
    cohort_recovery.add_argument("--confirm", action="store_true")
    cohort_recovery.set_defaults(
        handler=_prepare_phase8_cohort_recovery_successor
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (PipelineError, BudgetExceeded) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
