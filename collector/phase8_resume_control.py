"""Audited source-only continuation for the active Phase 8 scanner run.

This control certifies the two orchestration fixes discovered while resuming
the immutable Cohort A task universe.  It changes only the reviewed network
source identity in the run plan.  Tasks, attempts, results, fingerprints,
budgets, and all earlier certificates remain byte-for-byte compatible.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping

from .fingerprints import canonical_json
from .phase8_control import _sha256
from .pipeline import (
    PHASE8_MAX_OWNER_WALL_SECONDS,
    PipelineError,
    RunBudgets,
    _network_task_source_sha256,
    _validate_reviewed_execution_contract,
)
from .planner import current_fingerprints
from .state import StateDB
from .successor import (
    _CURRENT_NETWORK_TASK_PATHS,
    _git,
    _source_payload_sha256,
)


_PREDECESSOR_COMMIT = "3c40267b9844a84aa6d08c2f6a897c81a950fcb4"
_REQUIRED_CONTROL_COMMITS = (
    "3ffc6eb48d33040ea6e218499a89444f75050997",
    "6b9528d7f6c5f2506ecee15f18bde56a81886bff",
)
_CHANGED_PATHS = frozenset({
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
})
_TASK_UNIVERSE = 38321
_CONTROL_STAGE = "phase8_scanner_resume_control"


def _query_proof(
    state: StateDB,
    sql: str,
    params: Iterable[Any] = (),
) -> dict[str, Any]:
    """Stream a deterministic row proof without materializing large tables."""
    digest = hashlib.sha256()
    count = 0
    for row in state.connection.execute(sql, tuple(params)):
        document = {key: row[key] for key in row.keys()}
        payload = canonical_json(document).encode("utf-8")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        count += 1
    return {"row_count": count, "rows_sha256": digest.hexdigest()}


def _preserved_state_snapshot(state: StateDB, run_id: str) -> dict[str, Any]:
    """Hash every scanner datum and every pre-existing stage certificate."""
    task_status_counts = {
        status: 0 for status in ("complete", "failed", "pending", "running")
    }
    for row in state.connection.execute(
        """
        SELECT status,COUNT(*) AS count
        FROM tasks WHERE run_id=? AND stage='scan'
        GROUP BY status ORDER BY status
        """,
        (run_id,),
    ):
        if row["status"] not in task_status_counts:
            raise PipelineError("scanner resume control found an invalid task state")
        task_status_counts[str(row["status"])] = int(row["count"])

    snapshot = {
        "task_status_counts": task_status_counts,
        "tasks": _query_proof(
            state,
            """
            SELECT task_id,run_id,stage,task_key,repository_id,library_id,
                   payload_json,result_json,status,attempts,max_attempts,
                   lease_owner,lease_expires_at,available_at,error_code,
                   created_at,updated_at,finished_at
            FROM tasks WHERE run_id=? ORDER BY task_id
            """,
            (run_id,),
        ),
        "scan_attempts": _query_proof(
            state,
            """
            SELECT task_id,attempt,run_id,repository_id,task_key,
                   payload_sha256,head_sha,status,retryable,error_code,
                   error_detail,seconds,current_tree_triage_seconds,
                   history_dating_seconds,analysis_seconds,
                   git_subprocess_count,network_clone_count,
                   network_fetch_count,network_materialized_bytes,
                   usage_complete,started_at,finished_at
            FROM scan_attempts WHERE run_id=? ORDER BY task_id,attempt
            """,
            (run_id,),
        ),
        "scan_results": _query_proof(
            state,
            """
            SELECT scan_result_id,repository_id,library_id,head_sha,
                   detector_fp,classification,status,evidence_json,
                   raw_first_commit,raw_first_date,derived_first_date,scanned_at
            FROM scan_results ORDER BY scan_result_id
            """,
        ),
        "prior_stages": _query_proof(
            state,
            """
            SELECT run_id,stage,status,counters_json,metrics_json,
                   checkpoint_json,started_at,finished_at,updated_at
            FROM stages WHERE run_id=? AND stage<>? ORDER BY stage
            """,
            (run_id, _CONTROL_STAGE),
        ),
        "run_invariants": _query_proof(
            state,
            """
            SELECT run_id,mode,budgets_json,fingerprints_json,base_release_id,
                   status,started_at,finished_at
            FROM runs WHERE run_id=?
            """,
            (run_id,),
        ),
    }
    snapshot["snapshot_sha256"] = _sha256(snapshot)
    return snapshot


def _source_audit(repo_root: Path, prior_network_sha256: str) -> dict[str, Any]:
    """Bind the certificate to the exact reviewed control-only commit chain."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError("scanner resume control requires a clean worktree")
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(
        _git(repo_root, "rev-parse", _PREDECESSOR_COMMIT + "^{commit}")
    ).strip()
    if predecessor != _PREDECESSOR_COMMIT or head == predecessor:
        raise PipelineError("scanner resume control source identity changed")
    commits = tuple(
        line
        for line in str(
            _git(
                repo_root,
                "rev-list",
                "--reverse",
                predecessor + ".." + head,
            )
        ).splitlines()
        if line
    )
    if (
        len(commits) != len(_REQUIRED_CONTROL_COMMITS) + 1
        or commits[:-1] != _REQUIRED_CONTROL_COMMITS
        or commits[-1] != head
    ):
        raise PipelineError("scanner resume control commit chain changed")
    changed_paths = tuple(
        sorted(
            line
            for line in str(
                _git(
                    repo_root,
                    "diff",
                    "--name-only",
                    predecessor + ".." + head,
                )
            ).splitlines()
            if line
        )
    )
    if set(changed_paths) != _CHANGED_PATHS:
        raise PipelineError("scanner resume control path set changed")
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("scanner resume control source audit failed")

    predecessor_payloads = {
        path: bytes(
            _git(repo_root, "show", predecessor + ":" + path, text=False)
        )
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior_network = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if (
        reproduced_prior_network != prior_network_sha256
        or current_network == prior_network_sha256
    ):
        raise PipelineError("scanner resume control network source proof changed")
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "required_control_commits": list(_REQUIRED_CONTROL_COMMITS),
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network_sha256,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _sha256(audit)
    return audit


def authorize_phase8_scanner_resume_control(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
    reason: str,
) -> dict[str, Any]:
    """Authorize only the reviewed source identity; preserve all scan state."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason or ""):
        raise PipelineError(
            "scanner resume control reason must be machine-readable"
        )
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError("scanner resume control requires the failed cohort run")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        migration = dict(contract["scanner_source_migration"])
        selected_library_ids = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("scanner resume control run contract is malformed") from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("scanner_resume_control") is not None
    ):
        raise PipelineError("scanner resume control run identity changed")
    prior_network = str(contract.get("network_task_source_sha256") or "")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", prior_network)
        or migration.get("current_network_task_source_sha256") != prior_network
        or migration.get("contract_sha256")
        != "fe7849a196e9fb4b4aa12f76e23b6946256f9e7ed647c668c01edada915f5959"
    ):
        raise PipelineError("scanner resume control predecessor contract changed")
    current_fingerprint_document = current_fingerprints().as_dict()
    if fingerprints != current_fingerprint_document:
        raise PipelineError("scanner resume control fingerprints changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("scanner resume control found a changed safety budget")

    audit = _source_audit(repo_root, prior_network)
    with state.transaction(immediate=True):
        before = _preserved_state_snapshot(state, run_id)
        counts = before["task_status_counts"]
        if (
            sum(counts.values()) != _TASK_UNIVERSE
            or counts["complete"] < 1
            or counts["running"] != 0
            or before["run_invariants"]["row_count"] != 1
        ):
            raise PipelineError("scanner resume control task universe changed")
        control = {
            "version": 1,
            "kind": "phase8-audited-scanner-resume-control",
            "policy": "source-only-durable-status-partition",
            "predecessor_source_commit": audit["predecessor_source_commit"],
            "successor_source_commit": audit["successor_source_commit"],
            "required_control_commits": audit["required_control_commits"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_fingerprints_sha256": _sha256(fingerprints),
            "current_fingerprints_sha256": _sha256(
                current_fingerprint_document
            ),
            "prior_network_task_source_sha256": prior_network,
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "scanner_migration_contract_sha256": migration[
                "contract_sha256"
            ],
            "task_universe_count": sum(counts.values()),
            "completed_scan_task_count": counts["complete"],
            "failed_scan_task_count": counts["failed"],
            "pending_scan_task_count": counts["pending"],
            "running_scan_task_count": counts["running"],
            "scan_attempt_count": before["scan_attempts"]["row_count"],
            "scan_result_count": before["scan_results"]["row_count"],
            "preserved_state_sha256": before["snapshot_sha256"],
        }
        control["contract_sha256"] = _sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["scanner_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected_library_ids,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError("scanner resume control validation changed")
        now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        changed = state.connection.execute(
            """
            UPDATE runs SET plan_json=?,checkpoint_at=?
            WHERE run_id=? AND status='failed' AND plan_json=?
            """,
            (canonical_json(updated_plan), now, run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError("scanner resume control run changed concurrently")
        state.update_stage(
            run_id,
            _CONTROL_STAGE,
            status="complete",
            counters={
                "task_universe_count": sum(counts.values()),
                "completed_scan_tasks_preserved": counts["complete"],
                "failed_scan_tasks_preserved": counts["failed"],
                "pending_scan_tasks_preserved": counts["pending"],
            },
            metrics={
                "reset_scan_tasks": 0,
                "changed_scan_results": 0,
                "other_budget_changes": 0,
            },
            checkpoint={
                "reason": reason,
                "authorized_at": now,
                "source_audit": audit,
                "control": control,
                "preserved_state": before,
            },
        )
        after = _preserved_state_snapshot(state, run_id)
        if after != before:
            raise PipelineError("scanner resume control changed preserved state")
    return {
        "run_id": run_id,
        "status": run["status"],
        "control": control,
        "reset_scan_tasks": 0,
        "changed_scan_results": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }
