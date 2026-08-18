"""Owner-authorized stop boundary for the Phase 8 scan retry tail.

The control is deliberately incident-specific.  It closes only an expired
coordinator attempt, changes pending scan tasks to terminal deferred failures,
records the exact repository/task set, and updates the reviewed source identity
so the same run can continue through aggregation, citations, validation, and
the owner gate without asserting clean-negative evidence for skipped work.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import os
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .fingerprints import canonical_json, fingerprint
from .pipeline import (
    PHASE8_MAX_OWNER_WALL_SECONDS,
    PHASE8_SCAN_TASK_UNIVERSE,
    PipelineError,
    RunBudgets,
    _canonical_sha256,
    _graphql_journal_budget,
    _network_task_source_sha256,
    _validate_phase8_privacy_resume_control,
    _validate_phase8_fresh_candidate_deferral_control,
    _validate_phase8_visibility_rejection_resume_control,
    _validate_phase8_visibility_refresh_resume_control,
    _validate_phase8_visibility_budget_resume_control,
    _validate_phase8_visibility_transport_retry_control,
    _validate_phase8_visibility_epoch_recovery_control,
    _validate_phase8_post_refresh_privacy_control,
    _validate_phase8_final_visibility_privacy_control,
    _validate_phase8_visibility_set_resume_control,
    _validate_reviewed_execution_contract,
)
from .planner import current_fingerprints
from .state import StateDB
from .successor import (
    _CURRENT_NETWORK_TASK_PATHS,
    _git,
    _source_payload_sha256,
)


_PREDECESSOR_COMMIT = "511a0d005bc065f5ff437225370915f7c41b43e5"
_CHANGED_PATHS = frozenset({
    ".gitlab-ci.yml",
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "collector/publish_v2.py",
    "collector/state.py",
    "collector/validate_v2.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
})
_CONTROL_STAGE = "phase8_scan_tail_deferral"
_RESUME_PREDECESSOR_COMMIT = "55574deb6598dc332530750e40c56b629c157f91"
_RESUME_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "collector/state.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
})
_RESUME_CONTROL_STAGE = "phase8_scan_tail_resume_control"
_DOWNSTREAM_PREDECESSOR_COMMIT = (
    "c02882128a069d84bfe3e6102648aaf5738efff3"
)
_DOWNSTREAM_SEMANTICS_COMMIT = (
    "25b94eaf03b93a1f3f4be35941848941a5982744"
)
_DOWNSTREAM_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "collector/validate_v2.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
    "test_req14_publication.py",
})
_DOWNSTREAM_CONTROL_STAGE = "phase8_downstream_resume_control"
_VISIBILITY_PREDECESSOR_COMMIT = (
    "75693f5a14187713e2b04bbd5ce8bb3ac1114fc5"
)
_VISIBILITY_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_VISIBILITY_CONTROL_STAGE = "phase8_visibility_resume_control"
_GRAPHQL_PREDECESSOR_COMMIT = "b826e8345304502c381be45ecce2a44de399bd7b"
_GRAPHQL_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_GRAPHQL_CONTROL_STAGE = "phase8_graphql_resume_control"
_PRIVACY_PREDECESSOR_COMMIT = "4ebb8d6db10171aa3e06117f8e62dce94ac01d38"
_PRIVACY_CHANGED_PATHS = frozenset({
    "collector/cli.py", "collector/phase8_tail_control.py",
    "collector/pipeline.py", "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md", "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_PRIVACY_CONTROL_STAGE = "phase8_privacy_resume_control"
_FRESH_CANDIDATE_PREDECESSOR_COMMIT = (
    "c97fe1a2f6d8e1f3c1d413707c41ee5da7187e51"
)
_FRESH_CANDIDATE_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_FRESH_CANDIDATE_CONTROL_STAGE = (
    "phase8_fresh_candidate_deferral_control"
)
_VISIBILITY_SET_PREDECESSOR_COMMIT = (
    "05a4e6a335ef3527c5a03326a656175a0103380f"
)
_VISIBILITY_SET_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_VISIBILITY_SET_CONTROL_STAGE = "phase8_visibility_set_resume_control"
_VISIBILITY_REJECTION_PREDECESSOR_COMMIT = (
    "450eae2a0bac4d55d70e5aa9a5df099a20c2cf16"
)
_VISIBILITY_REJECTION_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_VISIBILITY_REJECTION_CONTROL_STAGE = (
    "phase8_visibility_rejection_resume_control"
)
_VISIBILITY_REFRESH_PREDECESSOR_COMMIT = (
    "6d39e84a6f26d0c0c5c1f153b0fbbcd02f39a0d5"
)
_VISIBILITY_REFRESH_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_VISIBILITY_REFRESH_CONTROL_STAGE = (
    "phase8_visibility_refresh_resume_control"
)
_VISIBILITY_BUDGET_PREDECESSOR_COMMIT = (
    "1b4ce9f401133aa689338a443ba5a575fad2039b"
)
_VISIBILITY_BUDGET_CHANGED_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_tail_control.py",
    "collector/pipeline.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_VISIBILITY_BUDGET_CONTROL_STAGE = (
    "phase8_visibility_budget_resume_control"
)
_VISIBILITY_TRANSPORT_RETRY_PREDECESSOR_COMMIT = (
    "c3198c950c52be0380f45eb40d1538adef61eb61"
)
_VISIBILITY_TRANSPORT_RETRY_CHANGED_PATHS = frozenset({
    "collector/cli.py", "collector/phase8_tail_control.py",
    "collector/pipeline.py", "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md", "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_VISIBILITY_TRANSPORT_RETRY_CONTROL_STAGE = (
    "phase8_visibility_transport_retry_control"
)
_VISIBILITY_EPOCH_RECOVERY_PREDECESSOR_COMMIT = (
    "f4df8cc4a7d0be1d75b7a17a8b39d427f12ef2ee"
)
_VISIBILITY_EPOCH_RECOVERY_CHANGED_PATHS = frozenset({
    "collector/cli.py", "collector/phase8_tail_control.py",
    "collector/pipeline.py", "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md", "test_req14_phase8_tail_control.py",
    "test_req14_pipeline.py",
})
_VISIBILITY_EPOCH_RECOVERY_CONTROL_STAGE = (
    "phase8_visibility_epoch_recovery_control"
)
_POST_REFRESH_PRIVACY_PREDECESSOR_COMMIT = (
    "0d6d2e43b8a6f719fcade685363d11a8774a1457"
)
_POST_REFRESH_PRIVACY_CHANGED_PATHS = frozenset({
    "collector/cli.py", "collector/phase8_tail_control.py",
    "collector/pipeline.py", "collector/state.py",
    "docs/Documentation.md", "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py", "test_req14_pipeline.py",
})
_POST_REFRESH_PRIVACY_CONTROL_STAGE = (
    "phase8_post_refresh_privacy_control"
)
_FINAL_VISIBILITY_PRIVACY_PREDECESSOR_COMMIT = (
    "f31ec517980c74f07e650129f49647ab000b252a"
)
_FINAL_VISIBILITY_PRIVACY_CHANGED_PATHS = frozenset({
    "collector/cli.py", "collector/phase8_tail_control.py",
    "collector/pipeline.py", "collector/state.py",
    "docs/Documentation.md", "docs/PROJECT-CONTEXT.md",
    "test_req14_phase8_tail_control.py", "test_req14_pipeline.py",
})
_FINAL_VISIBILITY_PRIVACY_CONTROL_STAGE = (
    "phase8_final_visibility_privacy_control"
)


def _query_proof(
    state: StateDB,
    sql: str,
    params: Iterable[Any] = (),
) -> dict[str, Any]:
    return _connection_query_proof(state.connection, sql, params)


def _connection_query_proof(
    connection: sqlite3.Connection,
    sql: str,
    params: Iterable[Any] = (),
) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    for row in connection.execute(sql, tuple(params)):
        payload = canonical_json(
            {key: row[key] for key in row.keys()}
        ).encode("utf-8")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        count += 1
    return {"row_count": count, "rows_sha256": digest.hexdigest()}


_SCAN_TASK_IMMUTABLE_SQL = """
    SELECT task_id,run_id,stage,task_key,repository_id,library_id,payload_json,
           attempts,max_attempts,lease_owner,lease_expires_at,available_at,
           error_code,created_at
    FROM tasks WHERE run_id=? AND stage='scan' ORDER BY task_id
"""
_SCAN_ATTEMPTS_SQL = """
    SELECT * FROM scan_attempts WHERE run_id=? ORDER BY task_id,attempt
"""
_SCAN_RESULTS_SQL = """
    SELECT * FROM scan_results ORDER BY scan_result_id
"""
_DEFERRED_TASK_SEMANTICS_SQL = """
    SELECT task_id,task_key,repository_id,library_id,payload_json,result_json,
           status,error_code,attempts,max_attempts
    FROM tasks WHERE run_id=? AND stage='scan' AND task_key IN ({placeholders})
    ORDER BY task_key
"""


def _deferred_task_semantics_proof(
    connection: sqlite3.Connection,
    run_id: str,
    task_keys: list[str],
) -> dict[str, Any]:
    return _connection_query_proof(
        connection,
        _DEFERRED_TASK_SEMANTICS_SQL.format(
            placeholders=",".join("?" for _ in task_keys)
        ),
        (run_id, *task_keys),
    )


def _load_deferred_task_repair(
    *,
    state: StateDB,
    run_id: str,
    deferral: dict[str, Any],
    repair_state_path: Path,
) -> tuple[list[tuple[Any, ...]], dict[str, Any]]:
    """Validate an independent pre-supersession state and return exact rows."""
    path = repair_state_path.resolve()
    if path == state.path.resolve() or not path.is_file():
        raise PipelineError(
            "downstream deferred-task repair state is absent or live"
        )
    task_keys = list(deferral["deferred_task_keys"])
    uri = "file:%s?mode=ro&immutable=1" % path.as_posix()
    reference = sqlite3.connect(uri, uri=True)
    reference.row_factory = sqlite3.Row
    try:
        check = reference.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise PipelineError(
                "downstream deferred-task repair state failed quick_check"
            )
        reference_run = reference.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        try:
            reference_deferral = json.loads(
                reference_run["plan_json"]
            )["execution_contract"]["scan_tail_deferral"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "downstream deferred-task repair contract is malformed"
            ) from exc
        if (
            reference_deferral.get("contract_sha256")
            != deferral.get("contract_sha256")
            or reference_deferral.get("deferred_task_keys_sha256")
            != deferral.get("deferred_task_keys_sha256")
            or reference_deferral.get("deferred_repository_proof_sha256")
            != deferral.get("deferred_repository_proof_sha256")
        ):
            raise PipelineError(
                "downstream deferred-task repair contract changed"
            )
        immutable_live = _connection_query_proof(
            state.connection, _SCAN_TASK_IMMUTABLE_SQL, (run_id,)
        )
        immutable_reference = _connection_query_proof(
            reference, _SCAN_TASK_IMMUTABLE_SQL, (run_id,)
        )
        attempts_live = _connection_query_proof(
            state.connection, _SCAN_ATTEMPTS_SQL, (run_id,)
        )
        attempts_reference = _connection_query_proof(
            reference, _SCAN_ATTEMPTS_SQL, (run_id,)
        )
        results_live = _connection_query_proof(
            state.connection, _SCAN_RESULTS_SQL
        )
        results_reference = _connection_query_proof(
            reference, _SCAN_RESULTS_SQL
        )
        if (
            immutable_live != immutable_reference
            or attempts_live != attempts_reference
            or results_live != results_reference
        ):
            raise PipelineError(
                "downstream deferred-task repair evidence changed"
            )
        placeholders = ",".join("?" for _ in task_keys)
        sql = (
            "SELECT * FROM tasks WHERE run_id=? AND stage='scan' "
            f"AND task_key IN ({placeholders}) ORDER BY task_key"
        )
        live_rows = state.connection.execute(
            sql, (run_id, *task_keys)
        ).fetchall()
        reference_rows = reference.execute(
            sql, (run_id, *task_keys)
        ).fetchall()
        if (
            len(live_rows) != len(task_keys)
            or len(reference_rows) != len(task_keys)
            or [row["task_key"] for row in live_rows] != task_keys
            or [row["task_key"] for row in reference_rows] != task_keys
        ):
            raise PipelineError(
                "downstream deferred-task repair set changed"
            )
        allowed_changes = {"result_json", "status", "updated_at", "finished_at"}
        columns = [item[1] for item in reference.execute(
            "PRAGMA table_info(tasks)"
        )]
        restore_rows = []
        for live, baseline in zip(live_rows, reference_rows):
            if (
                baseline["status"] != "failed"
                or live["status"] != "complete"
                or json.loads(live["result_json"] or "{}")
                != {"reason": "replanned_immutable_work", "superseded": True}
                or any(
                    live[column] != baseline[column]
                    for column in columns
                    if column not in allowed_changes
                )
            ):
                raise PipelineError(
                    "downstream deferred-task supersession shape changed"
                )
            restore_rows.append((baseline["result_json"], int(live["task_id"])))
        reference_semantics = _deferred_task_semantics_proof(
            reference, run_id, task_keys
        )
        return restore_rows, {
            "reference_path_name": path.name,
            "reference_deferred_tasks": reference_semantics,
            "reference_scan_attempts": attempts_reference,
            "reference_scan_results": results_reference,
            "immutable_scan_tasks": immutable_reference,
        }
    finally:
        reference.close()


def _status_counts(state: StateDB, run_id: str) -> dict[str, int]:
    result = {
        "complete": 0,
        "failed": 0,
        "pending": 0,
        "running": 0,
    }
    for row in state.connection.execute(
        """
        SELECT status,COUNT(*) AS count FROM tasks
        WHERE run_id=? AND stage='scan'
        GROUP BY status ORDER BY status
        """,
        (run_id,),
    ):
        if row["status"] not in result:
            raise PipelineError("scan-tail control found an invalid task state")
        result[str(row["status"])] = int(row["count"])
    return result


def _source_audit(repo_root: Path, prior_network: str) -> dict[str, Any]:
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError("scan-tail control requires a clean worktree")
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(
        _git(repo_root, "rev-parse", _PREDECESSOR_COMMIT + "^{commit}")
    ).strip()
    commits = tuple(
        line for line in str(
            _git(
                repo_root,
                "rev-list",
                "--reverse",
                predecessor + ".." + head,
            )
        ).splitlines() if line
    )
    if predecessor != _PREDECESSOR_COMMIT or commits != (head,):
        raise PipelineError("scan-tail control commit chain changed")
    changed_paths = tuple(sorted(
        line for line in str(
            _git(
                repo_root,
                "diff",
                "--name-only",
                predecessor + ".." + head,
            )
        ).splitlines() if line
    ))
    if set(changed_paths) != _CHANGED_PATHS:
        raise PipelineError("scan-tail control path set changed")
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("scan-tail control source audit failed")
    predecessor_payloads = {
        path: bytes(
            _git(repo_root, "show", predecessor + ":" + path, text=False)
        )
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError("scan-tail network source proof changed")
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _resume_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError("scan-tail resume control requires a clean worktree")
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(
        _git(
            repo_root,
            "rev-parse",
            _RESUME_PREDECESSOR_COMMIT + "^{commit}",
        )
    ).strip()
    commits = tuple(
        line for line in str(
            _git(
                repo_root,
                "rev-list",
                "--reverse",
                predecessor + ".." + head,
            )
        ).splitlines() if line
    )
    changed_paths = tuple(sorted(
        line for line in str(
            _git(
                repo_root,
                "diff",
                "--name-only",
                predecessor + ".." + head,
            )
        ).splitlines() if line
    ))
    if (
        predecessor != _RESUME_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _RESUME_CHANGED_PATHS
    ):
        raise PipelineError("scan-tail resume source boundary changed")
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("scan-tail resume source audit failed")
    predecessor_payloads = {
        path: bytes(
            _git(repo_root, "show", predecessor + ":" + path, text=False)
        )
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError("scan-tail resume network source proof changed")
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _downstream_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove the exact staging and deferred-task repair commit chain."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "downstream resume control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(
        _git(
            repo_root,
            "rev-parse",
            _DOWNSTREAM_PREDECESSOR_COMMIT + "^{commit}",
        )
    ).strip()
    commits = tuple(
        line for line in str(
            _git(
                repo_root,
                "rev-list",
                "--reverse",
                predecessor + ".." + head,
            )
        ).splitlines() if line
    )
    changed_paths = tuple(sorted(
        line for line in str(
            _git(
                repo_root,
                "diff",
                "--name-only",
                predecessor + ".." + head,
            )
        ).splitlines() if line
    ))
    if (
        predecessor != _DOWNSTREAM_PREDECESSOR_COMMIT
        or commits != (_DOWNSTREAM_SEMANTICS_COMMIT, head)
        or set(changed_paths) != _DOWNSTREAM_CHANGED_PATHS
    ):
        raise PipelineError("downstream resume source boundary changed")
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("downstream resume source audit failed")
    predecessor_payloads = {
        path: bytes(
            _git(repo_root, "show", predecessor + ":" + path, text=False)
        )
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError("downstream resume network source proof changed")
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _visibility_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove one exact visibility-triggered metadata refresh correction."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "visibility resume control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root,
        "rev-parse",
        _VISIBILITY_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(
        line for line in str(_git(
            repo_root,
            "rev-list",
            "--reverse",
            predecessor + ".." + head,
        )).splitlines() if line
    )
    changed_paths = tuple(sorted(
        line for line in str(_git(
            repo_root,
            "diff",
            "--name-only",
            predecessor + ".." + head,
        )).splitlines() if line
    ))
    if (
        predecessor != _VISIBILITY_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _VISIBILITY_CHANGED_PATHS
    ):
        raise PipelineError("visibility resume source boundary changed")
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("visibility resume source audit failed")
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError("visibility resume network source proof changed")
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _graphql_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove one exact partial-epoch GraphQL accounting correction."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError("GraphQL resume control requires a clean worktree")
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root,
        "rev-parse",
        _GRAPHQL_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(
        line for line in str(_git(
            repo_root,
            "rev-list",
            "--reverse",
            predecessor + ".." + head,
        )).splitlines() if line
    )
    changed_paths = tuple(sorted(
        line for line in str(_git(
            repo_root,
            "diff",
            "--name-only",
            predecessor + ".." + head,
        )).splitlines() if line
    ))
    if (
        predecessor != _GRAPHQL_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _GRAPHQL_CHANGED_PATHS
    ):
        raise PipelineError("GraphQL resume source boundary changed")
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("GraphQL resume source audit failed")
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError("GraphQL resume network source proof changed")
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _privacy_source_audit(repo_root: Path, prior_network: str) -> dict[str, Any]:
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError("privacy resume control requires a clean worktree")
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root, "rev-parse", _PRIVACY_PREDECESSOR_COMMIT + "^{commit}"
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root, "rev-list", "--reverse", predecessor + ".." + head
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root, "diff", "--name-only", predecessor + ".." + head
    )).splitlines() if line))
    if (
        predecessor != _PRIVACY_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _PRIVACY_CHANGED_PATHS
    ):
        raise PipelineError("privacy resume source boundary changed")
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root, capture_output=True, text=True, check=False, timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("privacy resume source audit failed")
    predecessor_payloads = {
        path: bytes(_git(repo_root, "show", predecessor + ":" + path, text=False))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError("privacy resume network source proof changed")
    audit = {
        "version": 1, "predecessor_source_commit": predecessor,
        "successor_source_commit": head, "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _fresh_candidate_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "fresh-candidate deferral control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root,
        "rev-parse",
        _FRESH_CANDIDATE_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root, "rev-list", "--reverse", predecessor + ".." + head
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root, "diff", "--name-only", predecessor + ".." + head
    )).splitlines() if line))
    if (
        predecessor != _FRESH_CANDIDATE_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _FRESH_CANDIDATE_CHANGED_PATHS
    ):
        raise PipelineError(
            "fresh-candidate deferral source boundary changed"
        )
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("fresh-candidate deferral source audit failed")
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "fresh-candidate deferral network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _visibility_set_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove one exact failed final-visibility epoch correction."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "visibility-set resume control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root,
        "rev-parse",
        _VISIBILITY_SET_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root,
        "rev-list",
        "--reverse",
        predecessor + ".." + head,
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root,
        "diff",
        "--name-only",
        predecessor + ".." + head,
    )).splitlines() if line))
    if (
        predecessor != _VISIBILITY_SET_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _VISIBILITY_SET_CHANGED_PATHS
    ):
        raise PipelineError(
            "visibility-set resume source boundary changed"
        )
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("visibility-set resume source audit failed")
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "visibility-set resume network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _visibility_rejection_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove the exact newest-epoch missing-node refresh correction."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "visibility-rejection resume control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root,
        "rev-parse",
        _VISIBILITY_REJECTION_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root,
        "rev-list",
        "--reverse",
        predecessor + ".." + head,
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root,
        "diff",
        "--name-only",
        predecessor + ".." + head,
    )).splitlines() if line))
    if (
        predecessor != _VISIBILITY_REJECTION_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _VISIBILITY_REJECTION_CHANGED_PATHS
    ):
        raise PipelineError(
            "visibility-rejection resume source boundary changed"
        )
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError(
            "visibility-rejection resume source audit failed"
        )
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "visibility-rejection resume network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _visibility_refresh_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove the exact forced-refresh partial-epoch precedence fix."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "visibility-refresh resume control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root,
        "rev-parse",
        _VISIBILITY_REFRESH_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root,
        "rev-list",
        "--reverse",
        predecessor + ".." + head,
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root,
        "diff",
        "--name-only",
        predecessor + ".." + head,
    )).splitlines() if line))
    if (
        predecessor != _VISIBILITY_REFRESH_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _VISIBILITY_REFRESH_CHANGED_PATHS
    ):
        raise PipelineError(
            "visibility-refresh resume source boundary changed"
        )
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError(
            "visibility-refresh resume source audit failed"
        )
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "visibility-refresh resume network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _visibility_budget_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove the cohort-only, unchanged-budget batch-size correction."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "visibility-budget resume control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root,
        "rev-parse",
        _VISIBILITY_BUDGET_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root,
        "rev-list",
        "--reverse",
        predecessor + ".." + head,
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root,
        "diff",
        "--name-only",
        predecessor + ".." + head,
    )).splitlines() if line))
    if (
        predecessor != _VISIBILITY_BUDGET_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _VISIBILITY_BUDGET_CHANGED_PATHS
    ):
        raise PipelineError(
            "visibility-budget resume source boundary changed"
        )
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError(
            "visibility-budget resume source audit failed"
        )
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "visibility-budget resume network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _visibility_transport_retry_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove the exact malformed-response point-reserve correction."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "visibility transport retry control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root, "rev-parse",
        _VISIBILITY_TRANSPORT_RETRY_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root, "rev-list", "--reverse", predecessor + ".." + head,
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root, "diff", "--name-only", predecessor + ".." + head,
    )).splitlines() if line))
    if (
        predecessor != _VISIBILITY_TRANSPORT_RETRY_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _VISIBILITY_TRANSPORT_RETRY_CHANGED_PATHS
    ):
        raise PipelineError(
            "visibility transport retry source boundary changed"
        )
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root, capture_output=True, text=True, check=False, timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("visibility transport retry source audit failed")
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "visibility transport retry network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _visibility_epoch_recovery_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove the exact current-epoch selection and repair correction."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "visibility epoch recovery control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root, "rev-parse",
        _VISIBILITY_EPOCH_RECOVERY_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root, "rev-list", "--reverse", predecessor + ".." + head,
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root, "diff", "--name-only", predecessor + ".." + head,
    )).splitlines() if line))
    if (
        predecessor != _VISIBILITY_EPOCH_RECOVERY_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _VISIBILITY_EPOCH_RECOVERY_CHANGED_PATHS
    ):
        raise PipelineError("visibility epoch recovery source boundary changed")
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root, capture_output=True, text=True, check=False, timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("visibility epoch recovery source audit failed")
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "visibility epoch recovery network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _post_refresh_privacy_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove the exact recovered-epoch privacy continuation source."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "post-refresh privacy control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root, "rev-parse",
        _POST_REFRESH_PRIVACY_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root, "rev-list", "--reverse", predecessor + ".." + head,
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root, "diff", "--name-only", predecessor + ".." + head,
    )).splitlines() if line))
    if (
        predecessor != _POST_REFRESH_PRIVACY_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _POST_REFRESH_PRIVACY_CHANGED_PATHS
    ):
        raise PipelineError(
            "post-refresh privacy source boundary changed"
        )
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root, capture_output=True, text=True, check=False, timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError("post-refresh privacy source audit failed")
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "post-refresh privacy network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _final_visibility_privacy_source_audit(
    repo_root: Path,
    prior_network: str,
) -> dict[str, Any]:
    """Prove the exact final-visibility privacy continuation source."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "final-visibility privacy control requires a clean worktree"
        )
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(_git(
        repo_root, "rev-parse",
        _FINAL_VISIBILITY_PRIVACY_PREDECESSOR_COMMIT + "^{commit}",
    )).strip()
    commits = tuple(line for line in str(_git(
        repo_root, "rev-list", "--reverse", predecessor + ".." + head,
    )).splitlines() if line)
    changed_paths = tuple(sorted(line for line in str(_git(
        repo_root, "diff", "--name-only", predecessor + ".." + head,
    )).splitlines() if line))
    if (
        predecessor != _FINAL_VISIBILITY_PRIVACY_PREDECESSOR_COMMIT
        or commits != (head,)
        or set(changed_paths) != _FINAL_VISIBILITY_PRIVACY_CHANGED_PATHS
    ):
        raise PipelineError(
            "final-visibility privacy source boundary changed"
        )
    checked = subprocess.run(
        ["git", "diff", "--check", predecessor + ".." + head],
        cwd=repo_root, capture_output=True, text=True, check=False, timeout=30,
    )
    if checked.returncode or checked.stdout or checked.stderr:
        raise PipelineError(
            "final-visibility privacy source audit failed"
        )
    predecessor_payloads = {
        path: bytes(_git(
            repo_root, "show", predecessor + ":" + path, text=False
        ))
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    reproduced_prior = _source_payload_sha256(
        predecessor_payloads, _CURRENT_NETWORK_TASK_PATHS
    )
    current_network = _network_task_source_sha256()
    if reproduced_prior != prior_network or current_network == prior_network:
        raise PipelineError(
            "final-visibility privacy network source proof changed"
        )
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "successor_source_commit": head,
        "changed_paths": list(changed_paths),
        "prior_network_task_source_sha256": prior_network,
        "current_network_task_source_sha256": current_network,
    }
    audit["source_audit_sha256"] = _canonical_sha256(audit)
    return audit


def _resume_preserved_state(
    state: StateDB,
    run_id: str,
) -> dict[str, Any]:
    snapshot = {
        "tasks": _query_proof(
            state,
            """
            SELECT task_id,run_id,stage,task_key,repository_id,library_id,
                   payload_json,result_json,attempts,max_attempts,created_at
            FROM tasks WHERE run_id=? ORDER BY task_id
            """,
            (run_id,),
        ),
        "scan_attempts": _query_proof(
            state,
            """
            SELECT task_id,attempt,run_id,repository_id,task_key,payload_sha256,
                   head_sha,status,retryable,error_code,error_detail,seconds,
                   current_tree_triage_seconds,history_dating_seconds,
                   analysis_seconds,git_subprocess_count,network_clone_count,
                   network_fetch_count,network_materialized_bytes,usage_complete,
                   started_at,finished_at
            FROM scan_attempts WHERE run_id=? ORDER BY task_id,attempt
            """,
            (run_id,),
        ),
        "scan_results": _query_proof(
            state,
            """
            SELECT scan_result_id,repository_id,library_id,head_sha,detector_fp,
                   classification,status,evidence_json,raw_first_commit,
                   raw_first_date,derived_first_date,scanned_at
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
            (run_id, _RESUME_CONTROL_STAGE),
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
    snapshot["snapshot_sha256"] = _canonical_sha256(snapshot)
    return snapshot


def _downstream_preserved_state(
    state: StateDB,
    run_id: str,
    *,
    control_stage: str = _DOWNSTREAM_CONTROL_STAGE,
) -> dict[str, Any]:
    """Hash every durable input/cache the downstream control must preserve."""
    snapshot = {
        "tasks": _query_proof(
            state,
            "SELECT * FROM tasks WHERE run_id=? ORDER BY task_id",
            (run_id,),
        ),
        "scan_attempts": _query_proof(
            state,
            """
            SELECT * FROM scan_attempts WHERE run_id=?
            ORDER BY task_id,attempt
            """,
            (run_id,),
        ),
        "scan_results": _query_proof(
            state,
            "SELECT * FROM scan_results ORDER BY scan_result_id",
        ),
        "candidates": _query_proof(
            state,
            "SELECT * FROM candidates ORDER BY candidate_id",
        ),
        "repositories": _query_proof(
            state,
            "SELECT * FROM repositories ORDER BY node_id",
        ),
        "repo_analysis": _query_proof(
            state,
            """
            SELECT * FROM repo_analysis
            ORDER BY repository_id,head_sha,ai_fp
            """,
        ),
        "libraries": _query_proof(
            state,
            "SELECT * FROM libraries ORDER BY library_id",
        ),
        "discovery_coverage": _query_proof(
            state,
            """
            SELECT * FROM discovery_coverage
            ORDER BY run_id,library_id,source,query_fp,partition_key
            """,
        ),
        "network_task_usage": _query_proof(
            state,
            """
            SELECT * FROM network_task_usage
            ORDER BY run_id,task_id,attempt
            """,
        ),
        "citation_cache": _query_proof(
            state,
            """
            SELECT * FROM citation_cache
            ORDER BY library_id,query_fp,work_id
            """,
        ),
        "prior_stages": _query_proof(
            state,
            """
            SELECT * FROM stages WHERE run_id=? AND stage<>?
            ORDER BY stage
            """,
            (run_id, control_stage),
        ),
        "run_invariants": _query_proof(
            state,
            """
            SELECT run_id,mode,budgets_json,fingerprints_json,
                   base_release_id,status,started_at,finished_at
            FROM runs WHERE run_id=?
            """,
            (run_id,),
        ),
    }
    snapshot["snapshot_sha256"] = _canonical_sha256(snapshot)
    return snapshot


def _deferred_rows(state: StateDB, run_id: str) -> list[dict[str, Any]]:
    result = []
    for row in state.connection.execute(
        """
        SELECT task_id,task_key,repository_id,payload_json,status,error_code,
               attempts,max_attempts
        FROM tasks WHERE run_id=? AND stage='scan' AND status!='complete'
        ORDER BY task_key
        """,
        (run_id,),
    ):
        try:
            payload = json.loads(row["payload_json"] or "{}")
            full_name = payload["full_name"]
            head_sha = payload["head_sha"]
            libraries = sorted(payload["libraries"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PipelineError("scan-tail task payload is malformed") from exc
        if (
            not isinstance(full_name, str)
            or not isinstance(head_sha, str)
            or not isinstance(libraries, list)
            or not all(isinstance(item, str) for item in libraries)
        ):
            raise PipelineError("scan-tail task payload identity is invalid")
        result.append({
            "task_id": int(row["task_id"]),
            "task_key": str(row["task_key"]),
            "repository_id": str(row["repository_id"]),
            "full_name": full_name,
            "head_sha": head_sha,
            "libraries": libraries,
            "status": str(row["status"]),
            "error_code": row["error_code"],
            "attempts": int(row["attempts"]),
            "max_attempts": int(row["max_attempts"]),
        })
    return result


def _repository_proof_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "task_key": row["task_key"],
        "repository_id": row["repository_id"],
        "full_name": row["full_name"],
        "head_sha": row["head_sha"],
        "libraries": row["libraries"],
    } for row in rows]


def _write_note(
    state: StateDB,
    run_id: str,
    control: dict[str, Any],
    rows: list[dict[str, Any]],
) -> Path:
    note = state.path.parent / f"phase8-deferred-repositories-{run_id}.json"
    temporary = note.with_name(f".{note.name}.tmp-{os.getpid()}")
    document = {
        "version": 1,
        "kind": "phase8-deferred-repository-note",
        "run_id": run_id,
        "deferral_contract_sha256": control["contract_sha256"],
        "deferred_repository_count": len(rows),
        "repositories": rows,
    }
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, note)
    return note


def authorize_phase8_scan_tail_deferral(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
    reason: str,
) -> dict[str, Any]:
    """Freeze the exact unresolved tail and authorize downstream work."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason or ""):
        raise PipelineError("scan-tail deferral reason must be machine-readable")
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if (
        run is None
        or run["mode"] != "reconcile"
        or run["status"] not in {"running", "failed"}
    ):
        raise PipelineError("scan-tail deferral requires the interrupted cohort run")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected_library_ids = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("scan-tail run contract is malformed") from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("scanner_resume_control") is None
        or contract.get("scan_tail_deferral") is not None
    ):
        raise PipelineError("scan-tail run identity changed")
    prior_network = str(contract.get("network_task_source_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", prior_network):
        raise PipelineError("scan-tail predecessor source identity is invalid")
    if fingerprints != current_fingerprints().as_dict():
        raise PipelineError("scan-tail detector fingerprints changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("scan-tail control found a changed safety budget")
    audit = _source_audit(repo_root, prior_network)
    now_epoch = datetime.datetime.now(datetime.timezone.utc).timestamp()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )

    with state.transaction(immediate=True):
        before_counts = _status_counts(state, run_id)
        if (
            sum(before_counts.values()) != PHASE8_SCAN_TASK_UNIVERSE
            or before_counts["complete"] < 1
            or before_counts["pending"] + before_counts["failed"]
            + before_counts["running"] < 1
        ):
            raise PipelineError("scan-tail task universe changed")
        live = state.connection.execute(
            """
            SELECT task_id FROM tasks WHERE run_id=? AND stage='scan'
              AND status='running' AND lease_expires_at>?
            """,
            (run_id, now_epoch),
        ).fetchall()
        if live:
            raise PipelineError("scan-tail control found a live scan lease")
        before_attempts = _query_proof(
            state,
            """
            SELECT task_id,attempt,run_id,repository_id,task_key,payload_sha256,
                   head_sha,status,retryable,error_code,error_detail,seconds,
                   current_tree_triage_seconds,history_dating_seconds,
                   analysis_seconds,git_subprocess_count,network_clone_count,
                   network_fetch_count,network_materialized_bytes,usage_complete,
                   started_at,finished_at
            FROM scan_attempts WHERE run_id=? ORDER BY task_id,attempt
            """,
            (run_id,),
        )
        scan_results = _query_proof(
            state,
            """
            SELECT scan_result_id,repository_id,library_id,head_sha,detector_fp,
                   classification,status,evidence_json,raw_first_commit,
                   raw_first_date,derived_first_date,scanned_at
            FROM scan_results ORDER BY scan_result_id
            """,
        )
        completed_tasks = _query_proof(
            state,
            """
            SELECT task_id,run_id,stage,task_key,repository_id,library_id,
                   payload_json,result_json,status,attempts,max_attempts,
                   lease_owner,lease_expires_at,available_at,error_code,
                   created_at,updated_at,finished_at
            FROM tasks WHERE run_id=? AND stage='scan' AND status='complete'
            ORDER BY task_id
            """,
            (run_id,),
        )
        original_rows = _deferred_rows(state, run_id)
        original_by_id = {row["task_id"]: row for row in original_rows}

        interrupted = state.connection.execute(
            """
            UPDATE scan_attempts SET status='interrupted',retryable=1,
                error_code=COALESCE(error_code,'coordinator_interrupted'),
                usage_complete=0,finished_at=?
            WHERE run_id=? AND status='running'
            """,
            (now, run_id),
        ).rowcount
        running_tasks = state.connection.execute(
            """
            SELECT * FROM tasks WHERE run_id=? AND stage='scan'
              AND status='running' ORDER BY task_id
            """,
            (run_id,),
        ).fetchall()
        for task in running_tasks:
            status, error_code = state._scan_task_recovery_disposition(task)
            if status != "failed":
                raise PipelineError("expired scan-tail attempt did not fail closed")
            state.connection.execute(
                """
                UPDATE tasks SET status='failed',lease_owner=NULL,
                    lease_expires_at=NULL,error_code=?,updated_at=?,finished_at=?
                WHERE task_id=?
                """,
                (error_code, now, now, task["task_id"]),
            )
        state.connection.execute(
            """
            UPDATE tasks SET status='failed',lease_owner=NULL,
                lease_expires_at=NULL,
                error_code=COALESCE(error_code,'owner_deferred_scan_tail'),
                updated_at=?,finished_at=?
            WHERE run_id=? AND stage='scan' AND status='pending'
            """,
            (now, now, run_id),
        )
        after_counts = _status_counts(state, run_id)
        if after_counts != {
            "complete": before_counts["complete"],
            "failed": PHASE8_SCAN_TASK_UNIVERSE - before_counts["complete"],
            "pending": 0,
            "running": 0,
        }:
            raise PipelineError("scan-tail terminal partition changed")
        final_rows = _deferred_rows(state, run_id)
        task_keys = [row["task_key"] for row in final_rows]
        repository_proof = _repository_proof_rows(final_rows)
        if len(task_keys) != after_counts["failed"]:
            raise PipelineError("scan-tail deferred set changed")

        control = {
            "version": 1,
            "kind": "phase8-owner-scan-tail-deferral",
            "policy": "quarantine-exact-unresolved-repositories",
            "reason": reason,
            "authorized_at": now,
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": prior_network,
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "task_universe_count": PHASE8_SCAN_TASK_UNIVERSE,
            "completed_scan_task_count": after_counts["complete"],
            "deferred_scan_task_count": after_counts["failed"],
            "deferred_task_keys": task_keys,
            "deferred_task_keys_sha256": _canonical_sha256(task_keys),
            "deferred_repository_proof_sha256": _canonical_sha256(
                repository_proof
            ),
            "status_counts_before": before_counts,
            "status_counts_after": after_counts,
            "interrupted_attempts_closed": interrupted,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["scan_tail_deferral"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected_library_ids,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError("scan-tail reviewed contract changed")
        after_attempts = _query_proof(
            state,
            """
            SELECT task_id,attempt,run_id,repository_id,task_key,payload_sha256,
                   head_sha,status,retryable,error_code,error_detail,seconds,
                   current_tree_triage_seconds,history_dating_seconds,
                   analysis_seconds,git_subprocess_count,network_clone_count,
                   network_fetch_count,network_materialized_bytes,usage_complete,
                   started_at,finished_at
            FROM scan_attempts WHERE run_id=? ORDER BY task_id,attempt
            """,
            (run_id,),
        )
        if before_attempts["row_count"] != after_attempts["row_count"]:
            raise PipelineError("scan-tail control created an attempt")
        if scan_results != _query_proof(
            state,
            """
            SELECT scan_result_id,repository_id,library_id,head_sha,detector_fp,
                   classification,status,evidence_json,raw_first_commit,
                   raw_first_date,derived_first_date,scanned_at
            FROM scan_results ORDER BY scan_result_id
            """,
        ):
            raise PipelineError("scan-tail control changed scan results")
        if completed_tasks != _query_proof(
            state,
            """
            SELECT task_id,run_id,stage,task_key,repository_id,library_id,
                   payload_json,result_json,status,attempts,max_attempts,
                   lease_owner,lease_expires_at,available_at,error_code,
                   created_at,updated_at,finished_at
            FROM tasks WHERE run_id=? AND stage='scan' AND status='complete'
            ORDER BY task_id
            """,
            (run_id,),
        ):
            raise PipelineError("scan-tail control changed completed tasks")
        if set(original_by_id) != {row["task_id"] for row in final_rows}:
            raise PipelineError("scan-tail unresolved identity set changed")

        changed = state.connection.execute(
            """
            UPDATE runs SET plan_json=?,status='failed',finished_at=?,
                checkpoint_at=?
            WHERE run_id=? AND plan_json=? AND status IN ('running','failed')
            """,
            (
                canonical_json(updated_plan),
                now,
                now,
                run_id,
                run["plan_json"],
            ),
        ).rowcount
        if changed != 1:
            raise PipelineError("scan-tail run changed concurrently")
        state.update_stage(run_id, "scan", status="failed")
        state.update_stage(
            run_id,
            _CONTROL_STAGE,
            status="complete",
            counters={
                "task_universe_count": PHASE8_SCAN_TASK_UNIVERSE,
                "completed_scan_tasks_preserved": after_counts["complete"],
                "deferred_scan_tasks": after_counts["failed"],
                "interrupted_attempts_closed": interrupted,
            },
            metrics={
                "status_counts_before": before_counts,
                "status_counts_after": after_counts,
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "other_budget_changes": 0,
            },
            checkpoint={
                "reason": reason,
                "authorized_at": now,
                "deferral_contract_sha256": control["contract_sha256"],
                "deferred_task_keys_sha256": control[
                    "deferred_task_keys_sha256"
                ],
                "deferred_repository_proof_sha256": control[
                    "deferred_repository_proof_sha256"
                ],
                "attempts_before": before_attempts,
                "attempts_after": after_attempts,
                "scan_results": scan_results,
                "completed_tasks": completed_tasks,
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "other_budget_changes": 0,
            },
        )

    note_rows = []
    for final in final_rows:
        original = original_by_id[final["task_id"]]
        note_rows.append({
            **final,
            "status_before": original["status"],
            "error_code_before": original["error_code"],
            "status_after": final["status"],
            "error_code_after": final["error_code"],
        })
    note = _write_note(state, run_id, control, note_rows)
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "deferred_repository_count": len(final_rows),
        "interrupted_attempts_closed": interrupted,
        "note_path": str(note),
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_scan_tail_resume_control(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
) -> dict[str, Any]:
    """Adopt the exact quarantine grouping and terminal-state correction."""
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError("scan-tail resume control requires the failed cohort run")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        deferral = dict(contract["scan_tail_deferral"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected_library_ids = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("scan-tail resume run contract is malformed") from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("scan_tail_resume_control") is not None
        or deferral.get("kind") != "phase8-owner-scan-tail-deferral"
        or deferral.get("current_network_task_source_sha256")
        != contract.get("network_task_source_sha256")
    ):
        raise PipelineError("scan-tail resume run identity changed")
    if fingerprints != current_fingerprints().as_dict():
        raise PipelineError("scan-tail resume detector fingerprints changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("scan-tail resume found a changed safety budget")
    audit = _resume_source_audit(
        repo_root,
        deferral["current_network_task_source_sha256"],
    )
    with state.transaction(immediate=True):
        before = _resume_preserved_state(state, run_id)
        counts = _status_counts(state, run_id)
        if (
            counts["complete"]
            != deferral.get("completed_scan_task_count")
            or counts["failed"] + counts["pending"]
            != deferral.get("deferred_scan_task_count")
            or counts["running"] != 0
        ):
            raise PipelineError("scan-tail resume task partition changed")
        rows = _deferred_rows(state, run_id)
        if (
            _canonical_sha256([row["task_key"] for row in rows])
            != deferral.get("deferred_task_keys_sha256")
            or _canonical_sha256(_repository_proof_rows(rows))
            != deferral.get("deferred_repository_proof_sha256")
        ):
            raise PipelineError("scan-tail resume deferred set changed")
        running_attempts = state.connection.execute(
            """
            SELECT COUNT(*) FROM scan_attempts
            WHERE run_id=? AND status='running'
            """,
            (run_id,),
        ).fetchone()[0]
        if running_attempts:
            raise PipelineError("scan-tail resume found a running attempt")
        status_before = _query_proof(
            state,
            """
            SELECT task_id,task_key,status,error_code,attempts,max_attempts,
                   lease_owner,lease_expires_at,finished_at,updated_at
            FROM tasks
            WHERE run_id=? AND stage='scan' AND status!='complete'
            ORDER BY task_key
            """,
            (run_id,),
        )
        now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        reterminalized = state.connection.execute(
            """
            UPDATE tasks SET status='failed',lease_owner=NULL,
                lease_expires_at=NULL,
                error_code=COALESCE(error_code,'owner_deferred_scan_tail'),
                finished_at=COALESCE(finished_at,?),updated_at=?
            WHERE run_id=? AND stage='scan' AND status='pending'
            """,
            (now, now, run_id),
        ).rowcount
        if reterminalized != counts["pending"]:
            raise PipelineError("scan-tail resume terminal restoration changed")
        counts_after = _status_counts(state, run_id)
        if counts_after != deferral.get("status_counts_after"):
            raise PipelineError("scan-tail resume terminal partition changed")
        rows_after = _deferred_rows(state, run_id)
        if (
            any(row["status"] != "failed" for row in rows_after)
            or _canonical_sha256([row["task_key"] for row in rows_after])
            != deferral.get("deferred_task_keys_sha256")
            or _canonical_sha256(_repository_proof_rows(rows_after))
            != deferral.get("deferred_repository_proof_sha256")
        ):
            raise PipelineError("scan-tail resume terminal proof changed")
        status_after = _query_proof(
            state,
            """
            SELECT task_id,task_key,status,error_code,attempts,max_attempts,
                   lease_owner,lease_expires_at,finished_at,updated_at
            FROM tasks
            WHERE run_id=? AND stage='scan' AND status!='complete'
            ORDER BY task_key
            """,
            (run_id,),
        )
        control = {
            "version": 1,
            "kind": "phase8-scan-tail-resume-control",
            "policy": "whole-repository-quarantine-grouping-compatibility",
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "scan_tail_deferral_contract_sha256": deferral[
                "contract_sha256"
            ],
            "task_universe_count": deferral["task_universe_count"],
            "completed_scan_task_count": deferral[
                "completed_scan_task_count"
            ],
            "deferred_scan_task_count": deferral[
                "deferred_scan_task_count"
            ],
            "deferred_task_keys_sha256": deferral[
                "deferred_task_keys_sha256"
            ],
            "deferred_repository_proof_sha256": deferral[
                "deferred_repository_proof_sha256"
            ],
            "preserved_state_sha256": before["snapshot_sha256"],
            "pre_control_status_counts": counts,
            "post_control_status_counts": counts_after,
            "pre_control_task_status_sha256": status_before["rows_sha256"],
            "post_control_task_status_sha256": status_after["rows_sha256"],
            "reterminalized_scan_task_count": reterminalized,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["scan_tail_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected_library_ids,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError("scan-tail resume reviewed contract changed")
        changed = state.connection.execute(
            """
            UPDATE runs SET plan_json=?,checkpoint_at=?
            WHERE run_id=? AND status='failed' AND plan_json=?
            """,
            (canonical_json(updated_plan), now, run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError("scan-tail resume run changed concurrently")
        state.update_stage(
            run_id,
            _RESUME_CONTROL_STAGE,
            status="complete",
            counters={
                "task_universe_count": deferral["task_universe_count"],
                "completed_scan_tasks_preserved": deferral[
                    "completed_scan_task_count"
                ],
                "deferred_scan_tasks_preserved": deferral[
                    "deferred_scan_task_count"
                ],
                "reterminalized_scan_tasks": reterminalized,
            },
            metrics={
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "other_budget_changes": 0,
            },
            checkpoint={
                "control": control,
                "preserved_state": before,
            },
        )
        after = _resume_preserved_state(state, run_id)
        if after != before:
            raise PipelineError("scan-tail resume changed preserved state")
        state._assert_run_publishable(run_id)
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "other_budget_changes": 0,
        "reterminalized_scan_tasks": reterminalized,
        "launchd_armed": False,
    }


def authorize_phase8_downstream_resume_control(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
    repair_state_path: Path | None = None,
) -> dict[str, Any]:
    """Adopt staging corrections and repair only the certified supersession."""
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "downstream resume control requires the failed cohort run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        tail_resume = dict(contract["scan_tail_resume_control"])
        deferral = dict(contract["scan_tail_deferral"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected_library_ids = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "downstream resume run contract is malformed"
        ) from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("downstream_resume_control") is not None
        or tail_resume.get("kind") != "phase8-scan-tail-resume-control"
        or deferral.get("kind") != "phase8-owner-scan-tail-deferral"
        or tail_resume.get("current_network_task_source_sha256")
        != contract.get("network_task_source_sha256")
    ):
        raise PipelineError("downstream resume run identity changed")
    if fingerprints != current_fingerprints().as_dict():
        raise PipelineError("downstream resume detector fingerprints changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("downstream resume found a changed safety budget")
    stage_statuses = {
        row["stage"]: row["status"]
        for row in state.connection.execute(
            "SELECT stage,status FROM stages WHERE run_id=?",
            (run_id,),
        )
    }
    if any(
        stage_statuses.get(stage) != expected
        for stage, expected in (
            ("scan", "complete"),
            ("aggregation", "complete"),
            ("citations", "complete"),
            ("publication", "failed"),
        )
    ):
        raise PipelineError(
            "downstream resume requires the exact failed staging boundary"
        )
    audit = _downstream_source_audit(
        repo_root,
        tail_resume["current_network_task_source_sha256"],
    )
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    with state.transaction(immediate=True):
        task_keys = list(deferral["deferred_task_keys"])
        pre_repair_tasks = _deferred_task_semantics_proof(
            state.connection, run_id, task_keys
        )
        counts = _status_counts(state, run_id)
        expected_counts = {
            "complete": int(tail_resume["completed_scan_task_count"]),
            "failed": int(tail_resume["deferred_scan_task_count"]),
            "pending": 0,
            "running": 0,
        }
        repaired_scan_tasks = 0
        repair_source_tasks = pre_repair_tasks
        repair_source_attempts = _query_proof(
            state, _SCAN_ATTEMPTS_SQL, (run_id,)
        )
        repair_source_results = _query_proof(state, _SCAN_RESULTS_SQL)
        if counts != expected_counts:
            superseded_counts = {
                "complete": int(deferral["task_universe_count"]),
                "failed": 0,
                "pending": 0,
                "running": 0,
            }
            if counts != superseded_counts or repair_state_path is None:
                raise PipelineError(
                    "downstream resume scan partition changed"
                )
            restore_rows, repair_evidence = _load_deferred_task_repair(
                state=state,
                run_id=run_id,
                deferral=deferral,
                repair_state_path=repair_state_path,
            )
            repair_source_tasks = repair_evidence[
                "reference_deferred_tasks"
            ]
            repair_source_attempts = repair_evidence[
                "reference_scan_attempts"
            ]
            repair_source_results = repair_evidence[
                "reference_scan_results"
            ]
            superseded_result = canonical_json({
                "reason": "replanned_immutable_work",
                "superseded": True,
            })
            for result_json, task_id in restore_rows:
                repaired_scan_tasks += state.connection.execute(
                    """
                    UPDATE tasks SET status='failed',result_json=?,
                        lease_owner=NULL,lease_expires_at=NULL,
                        updated_at=?,finished_at=?
                    WHERE task_id=? AND status='complete' AND result_json=?
                    """,
                    (result_json, now, now, task_id, superseded_result),
                ).rowcount
            if repaired_scan_tasks != int(
                deferral["deferred_scan_task_count"]
            ):
                raise PipelineError(
                    "downstream deferred-task repair count changed"
                )
            counts = _status_counts(state, run_id)
        if counts != expected_counts:
            raise PipelineError(
                "downstream deferred-task terminal repair failed"
            )
        post_repair_tasks = _deferred_task_semantics_proof(
            state.connection, run_id, task_keys
        )
        if post_repair_tasks != repair_source_tasks:
            raise PipelineError(
                "downstream deferred-task repair result changed"
            )
        running_attempts = state.connection.execute(
            """
            SELECT COUNT(*) FROM scan_attempts
            WHERE run_id=? AND status='running'
            """,
            (run_id,),
        ).fetchone()[0]
        if running_attempts:
            raise PipelineError("downstream resume found a running attempt")
        before = _downstream_preserved_state(state, run_id)
        control = {
            "version": 1,
            "kind": "phase8-downstream-resume-control",
            "policy": (
                "publication-semantics-and-exact-deferred-task-repair-"
                "no-network-work"
            ),
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "scan_tail_resume_contract_sha256": tail_resume[
                "contract_sha256"
            ],
            "task_universe_count": deferral["task_universe_count"],
            "completed_scan_task_count": tail_resume[
                "completed_scan_task_count"
            ],
            "deferred_scan_task_count": tail_resume[
                "deferred_scan_task_count"
            ],
            "scan_attempt_count": before["scan_attempts"]["row_count"],
            "scan_result_count": before["scan_results"]["row_count"],
            "citation_cache_entry_count": before["citation_cache"][
                "row_count"
            ],
            "repaired_deferred_scan_task_count": repaired_scan_tasks,
            "pre_repair_deferred_tasks_sha256": pre_repair_tasks[
                "rows_sha256"
            ],
            "repair_source_deferred_tasks_sha256": repair_source_tasks[
                "rows_sha256"
            ],
            "post_repair_deferred_tasks_sha256": post_repair_tasks[
                "rows_sha256"
            ],
            "repair_source_scan_attempts_sha256": repair_source_attempts[
                "rows_sha256"
            ],
            "repair_source_scan_results_sha256": repair_source_results[
                "rows_sha256"
            ],
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["downstream_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected_library_ids,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError("downstream resume reviewed contract changed")
        changed = state.connection.execute(
            """
            UPDATE runs SET plan_json=?,checkpoint_at=?
            WHERE run_id=? AND status='failed' AND plan_json=?
            """,
            (canonical_json(updated_plan), now, run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError("downstream resume run changed concurrently")
        state.update_stage(
            run_id,
            _DOWNSTREAM_CONTROL_STAGE,
            status="complete",
            counters={
                "task_universe_count": deferral["task_universe_count"],
                "completed_scan_tasks_preserved": tail_resume[
                    "completed_scan_task_count"
                ],
                "deferred_scan_tasks_preserved": tail_resume[
                    "deferred_scan_task_count"
                ],
                "citation_cache_entries_preserved": before[
                    "citation_cache"
                ]["row_count"],
                "deferred_scan_tasks_repaired": repaired_scan_tasks,
            },
            metrics={
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={
                "control": control,
                "preserved_state": before,
                "pre_repair_deferred_tasks": pre_repair_tasks,
                "repair_source_deferred_tasks": repair_source_tasks,
                "post_repair_deferred_tasks": post_repair_tasks,
                "repair_source_scan_attempts": repair_source_attempts,
                "repair_source_scan_results": repair_source_results,
            },
        )
        after = _downstream_preserved_state(state, run_id)
        if after != before:
            raise PipelineError("downstream resume changed preserved state")
        state._assert_run_publishable(run_id)
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "repaired_deferred_scan_tasks": repaired_scan_tasks,
        "launchd_armed": False,
    }


def authorize_phase8_visibility_resume_control(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
) -> dict[str, Any]:
    """Adopt the exact fresh-metadata precedence fix after one missing node."""
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "visibility resume control requires the failed cohort run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        downstream = dict(contract["downstream_resume_control"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected_library_ids = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility resume run contract is malformed"
        ) from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("visibility_resume_control") is not None
        or downstream.get("kind") != "phase8-downstream-resume-control"
        or downstream.get("current_network_task_source_sha256")
        != contract.get("network_task_source_sha256")
    ):
        raise PipelineError("visibility resume run identity changed")
    if fingerprints != current_fingerprints().as_dict():
        raise PipelineError("visibility resume detector fingerprints changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("visibility resume found a changed safety budget")
    stages = {
        row["stage"]: row["status"]
        for row in state.connection.execute(
            "SELECT stage,status FROM stages WHERE run_id=?", (run_id,)
        )
    }
    if (
        stages.get("final_visibility") != "failed"
        or stages.get("publication") != "failed"
    ):
        raise PipelineError(
            "visibility resume requires the exact failed attestation boundary"
        )
    visibility_tasks = state.connection.execute(
        """
        SELECT task_id,task_key,status,payload_json,result_json,
               lease_owner,lease_expires_at,error_code
        FROM tasks WHERE run_id=?
          AND stage='github-final-visibility-batch'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    status_counts: dict[str, int] = {}
    epochs = set()
    invalid = []
    for task in visibility_tasks:
        status_counts[str(task["status"])] = (
            status_counts.get(str(task["status"]), 0) + 1
        )
        try:
            payload = json.loads(task["payload_json"] or "{}")
            epoch = payload["epoch"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "visibility resume task payload is malformed"
            ) from exc
        epochs.add(epoch)
        if task["status"] != "complete":
            if (
                task["status"] != "pending"
                or task["result_json"] is not None
                or task["lease_owner"] is not None
                or task["lease_expires_at"] is not None
                or task["error_code"] is not None
            ):
                raise PipelineError(
                    "visibility resume pending task shape changed"
                )
            continue
        try:
            result = json.loads(task["result_json"] or "{}")
            repositories = result["repositories"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "visibility resume result is malformed"
            ) from exc
        if not isinstance(repositories, list):
            raise PipelineError("visibility resume result is malformed")
        for repository in repositories:
            if not isinstance(repository, dict):
                raise PipelineError("visibility resume result is malformed")
            public = (
                repository.get("admitted_public") is True
                and repository.get("status") == "ok"
                and repository.get("node_id")
                == repository.get("requested_node_id")
                and repository.get("requested_full_name") is None
                and repository.get("is_fork") is False
                and repository.get("is_archived") is False
            )
            if not public:
                invalid.append((task, repository))
    if (
        len(epochs) != 1
        or not visibility_tasks
        or status_counts.get("complete", 0) < 1
        or status_counts.get("pending", 0) < 1
        or set(status_counts) != {"complete", "pending"}
        or len(invalid) != 1
    ):
        raise PipelineError("visibility resume incident set changed")
    failed_task, missing = invalid[0]
    node_id = missing.get("requested_node_id")
    if (
        not isinstance(node_id, str)
        or not node_id
        or missing.get("request_key") != "node:" + node_id
        or missing.get("admitted_public") is not False
        or missing.get("status") != "missing"
        or missing.get("node_id") is not None
        or missing.get("full_name") is not None
        or missing.get("requested_full_name") is not None
        or missing.get("is_fork") is not None
        or missing.get("is_archived") is not None
        or missing.get("error_count") != 0
    ):
        raise PipelineError("visibility resume missing-node proof changed")
    epoch = next(iter(epochs))
    if not isinstance(epoch, str) or not re.fullmatch(r"[0-9a-f]{32}", epoch):
        raise PipelineError("visibility resume epoch changed")
    audit = _visibility_source_audit(
        repo_root,
        downstream["current_network_task_source_sha256"],
    )
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_CONTROL_STAGE,
        )
        control = {
            "version": 1,
            "kind": "phase8-visibility-resume-control",
            "policy": "force-fresh-metadata-after-exact-missing-node",
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "downstream_resume_contract_sha256": downstream[
                "contract_sha256"
            ],
            "visibility_epoch": epoch,
            "failed_visibility_task_key": str(failed_task["task_key"]),
            "missing_repository_node_sha256": hashlib.sha256(
                node_id.encode("utf-8")
            ).hexdigest(),
            "visibility_batch_count": len(visibility_tasks),
            "completed_visibility_batch_count": status_counts["complete"],
            "pending_visibility_batch_count": status_counts["pending"],
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["visibility_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected_library_ids,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError("visibility resume reviewed contract changed")
        changed = state.connection.execute(
            """
            UPDATE runs SET plan_json=?,checkpoint_at=?
            WHERE run_id=? AND status='failed' AND plan_json=?
            """,
            (canonical_json(updated_plan), now, run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError("visibility resume run changed concurrently")
        state.update_stage(
            run_id,
            _VISIBILITY_CONTROL_STAGE,
            status="complete",
            counters={
                "visibility_batches": len(visibility_tasks),
                "completed_visibility_batches": status_counts["complete"],
                "pending_visibility_batches": status_counts["pending"],
                "missing_repositories": 1,
            },
            metrics={
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_CONTROL_STAGE,
        )
        if after != before:
            raise PipelineError("visibility resume changed preserved state")
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "missing_repositories": 1,
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_graphql_resume_control(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
) -> dict[str, Any]:
    """Deduplicate embedded usage and resume the exact partial fresh epoch."""
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError("GraphQL resume control requires the failed run")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        visibility = dict(contract["visibility_resume_control"])
        preseeded = dict(contract["preseeded_metadata_epoch"])
        historical = dict(contract["historical_graphql_usage"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected_library_ids = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("GraphQL resume run contract is malformed") from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("graphql_resume_control") is not None
        or visibility.get("kind") != "phase8-visibility-resume-control"
        or visibility.get("current_network_task_source_sha256")
        != contract.get("network_task_source_sha256")
    ):
        raise PipelineError("GraphQL resume run identity changed")
    if fingerprints != current_fingerprints().as_dict():
        raise PipelineError("GraphQL resume detector fingerprints changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("GraphQL resume found a changed safety budget")
    stages = {
        row["stage"]: row["status"]
        for row in state.connection.execute(
            "SELECT stage,status FROM stages WHERE run_id=?", (run_id,)
        )
    }
    if (
        stages.get("metadata") != "failed"
        or stages.get("final_visibility") != "failed"
        or stages.get("publication") != "failed"
    ):
        raise PipelineError(
            "GraphQL resume requires the exact failed metadata boundary"
        )

    base_rows = state.connection.execute(
        """
        SELECT task_key,result_json FROM tasks
        WHERE run_id=? AND stage='github-metadata-batch'
          AND status='complete' AND task_key NOT LIKE 'fresh:%'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    result_universe = [{
        "task_key": str(row["task_key"]),
        "result_sha256": hashlib.sha256(
            str(row["result_json"]).encode("utf-8")
        ).hexdigest(),
    } for row in base_rows]
    embedded_result_sha256 = hashlib.sha256(
        canonical_json(result_universe).encode("utf-8")
    ).hexdigest()
    embedded_requests = 0
    embedded_points = 0
    try:
        for row in base_rows:
            document = json.loads(row["result_json"])
            if (
                document.get("version") != 2
                or document.get("kind") != "github-metadata-batch"
            ):
                raise ValueError("invalid embedded result")
            embedded_requests += int(document.get("request_count") or 0)
            embedded_points += int(document.get("points_used") or 0)
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "GraphQL resume embedded result is malformed"
        ) from exc
    if (
        len(base_rows) != preseeded.get("task_count")
        or embedded_result_sha256
        != preseeded.get("result_universe_sha256")
        or embedded_requests != int(historical.get("request_count") or 0)
        or embedded_points != int(historical.get("points_used") or 0)
        or historical.get("remaining") is not None
        or historical.get("reset_at") is not None
    ):
        raise PipelineError("GraphQL resume embedded usage proof changed")

    fresh_rows = state.connection.execute(
        """
        SELECT task_key,status,result_json,lease_owner,lease_expires_at,
               error_code,attempts,max_attempts FROM tasks
        WHERE run_id=? AND stage='github-metadata-batch'
          AND task_key LIKE 'fresh:%'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    epochs = {
        str(row["task_key"]).split(":", 2)[1] for row in fresh_rows
    }
    counts: dict[str, int] = {}
    retry_pending = 0
    for row in fresh_rows:
        counts[str(row["status"])] = counts.get(str(row["status"]), 0) + 1
        if row["status"] == "pending" and (
            row["result_json"] is not None
            or row["lease_owner"] is not None
            or row["lease_expires_at"] is not None
        ):
            raise PipelineError("GraphQL resume pending task shape changed")
        if row["status"] == "pending":
            pristine = row["attempts"] == 0 and row["error_code"] is None
            retryable = (
                row["attempts"] == 1
                and row["max_attempts"] == 3
                and row["error_code"] == "github-metadata-batch-failed"
            )
            if not pristine and not retryable:
                raise PipelineError(
                    "GraphQL resume pending attempt shape changed"
                )
            retry_pending += int(retryable)
    if (
        len(epochs) != 1
        or set(counts) != {"complete", "pending"}
        or counts["complete"] < 1
        or counts["pending"] < 1
    ):
        raise PipelineError("GraphQL resume fresh epoch changed")

    completed_requests = 0
    completed_points = 0
    for row in state.connection.execute(
        """
        SELECT result_json FROM tasks
        WHERE run_id=? AND status='complete'
          AND stage IN (
            'github-metadata-batch','github-final-visibility-batch'
          )
        ORDER BY task_id
        """,
        (run_id,),
    ):
        try:
            document = json.loads(row["result_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if (
            isinstance(document, dict)
            and document.get("version") == 2
            and document.get("kind") == "github-metadata-batch"
        ):
            completed_requests += int(document.get("request_count") or 0)
            completed_points += int(document.get("points_used") or 0)
    raw_points = embedded_points + completed_points
    if raw_points > budgets.max_graphql_points or (
        completed_points
        + counts["pending"]
        + visibility["visibility_batch_count"]
        > budgets.max_graphql_points
    ):
        raise PipelineError("GraphQL resume cannot fit the reviewed budget")

    audit = _graphql_source_audit(
        repo_root,
        visibility["current_network_task_source_sha256"],
    )
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state, run_id, control_stage=_GRAPHQL_CONTROL_STAGE
        )
        control = {
            "version": 1,
            "kind": "phase8-graphql-resume-control",
            "policy": (
                "deduplicate-embedded-preseeded-usage-and-resume-fresh-epoch"
            ),
            "predecessor_source_commit": audit["predecessor_source_commit"],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "visibility_resume_contract_sha256": visibility[
                "contract_sha256"
            ],
            "preseeded_metadata_contract_sha256": _canonical_sha256(
                preseeded
            ),
            "embedded_result_universe_sha256": embedded_result_sha256,
            "embedded_task_count": len(base_rows),
            "embedded_request_count": embedded_requests,
            "embedded_points_used": embedded_points,
            "fresh_metadata_epoch": next(iter(epochs)),
            "completed_fresh_metadata_batch_count": counts["complete"],
            "pending_fresh_metadata_batch_count": counts["pending"],
            "retry_pending_fresh_metadata_batch_count": retry_pending,
            "raw_graphql_points_used": raw_points,
            "reconciled_graphql_points_used": completed_points,
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["graphql_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected_library_ids,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError("GraphQL resume reviewed contract changed")
        changed = state.connection.execute(
            """
            UPDATE runs SET plan_json=?,checkpoint_at=?
            WHERE run_id=? AND status='failed' AND plan_json=?
            """,
            (canonical_json(updated_plan), now, run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError("GraphQL resume run changed concurrently")
        state.update_stage(
            run_id,
            _GRAPHQL_CONTROL_STAGE,
            status="complete",
            counters={
                "embedded_tasks": len(base_rows),
                "completed_fresh_batches": counts["complete"],
                "pending_fresh_batches": counts["pending"],
                "retry_pending_fresh_batches": retry_pending,
            },
            metrics={
                "raw_graphql_points_used": raw_points,
                "reconciled_graphql_points_used": completed_points,
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state, run_id, control_stage=_GRAPHQL_CONTROL_STAGE
        )
        if after != before:
            raise PipelineError("GraphQL resume changed preserved state")
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "embedded_points_deduplicated": embedded_points,
        "completed_fresh_metadata_batches": counts["complete"],
        "pending_fresh_metadata_batches": counts["pending"],
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_privacy_resume_control(
    *, state: StateDB, repo_root: Path, run_id: str, reference_state_path: Path,
) -> dict[str, Any]:
    """Adopt fresh privacy removals while pinning surviving scan evidence."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError("privacy resume control requires the failed run")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        graphql = dict(contract["graphql_resume_control"])
        deferral = dict(contract["scan_tail_deferral"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("privacy resume run contract is malformed") from exc
    if (
        contract.get("privacy_resume_control") is not None
        or graphql.get("kind") != "phase8-graphql-resume-control"
        or graphql.get("current_network_task_source_sha256")
        != contract.get("network_task_source_sha256")
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError("privacy resume run identity changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("privacy resume found a changed safety budget")
    if not reference_state_path.is_file():
        raise PipelineError("privacy resume reference state is missing")
    reference = sqlite3.connect(
        "file:%s?mode=ro" % reference_state_path.resolve(), uri=True
    )
    reference.row_factory = sqlite3.Row
    try:
        if reference.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise PipelineError("privacy resume reference state is invalid")
        prior_rows = reference.execute(
            """
            SELECT task_key,status,repository_id,payload_json FROM tasks
            WHERE run_id=? AND stage='scan' ORDER BY task_key
            """, (run_id,),
        ).fetchall()
    finally:
        reference.close()
    current_rows = state.connection.execute(
        """
        SELECT task_key,status,repository_id,payload_json FROM tasks
        WHERE run_id=? AND stage='scan' ORDER BY task_key
        """, (run_id,),
    ).fetchall()
    prior = {str(row["task_key"]): row for row in prior_rows}
    current = {str(row["task_key"]): row for row in current_rows}
    missing_keys = sorted(set(prior) - set(current))
    if set(current) - set(prior):
        raise PipelineError("privacy resume introduced scan tasks")
    missing_status = {"complete": 0, "failed": 0}
    for key in missing_keys:
        status = str(prior[key]["status"])
        if status not in missing_status:
            raise PipelineError("privacy resume purged task state changed")
        missing_status[status] += 1
        exists = state.connection.execute(
            "SELECT 1 FROM repositories WHERE node_id=?",
            (prior[key]["repository_id"],),
        ).fetchone()
        if exists is not None:
            raise PipelineError("privacy resume purged identity remains")
    original_deferred = set(deferral["deferred_task_keys"])
    remaining_keys = sorted(original_deferred & set(current))
    if original_deferred - set(current) != {
        key for key in missing_keys if prior[key]["status"] == "failed"
    }:
        raise PipelineError("privacy resume deferred purge set changed")
    proof_rows = []
    for key in remaining_keys:
        row = current[key]
        payload = json.loads(row["payload_json"])
        if row["status"] != "failed":
            raise PipelineError("privacy resume deferred status changed")
        proof_rows.append({
            "task_key": key, "repository_id": row["repository_id"],
            "full_name": payload["full_name"], "head_sha": payload["head_sha"],
            "libraries": sorted(payload["libraries"]),
        })
    current_counts = {str(row["status"]): 0 for row in current_rows}
    for row in current_rows:
        current_counts[str(row["status"])] = (
            current_counts.get(str(row["status"]), 0) + 1
        )
    if set(current_counts) != {"complete", "failed"}:
        raise PipelineError("privacy resume current scan partition changed")
    head_pins = state.connection.execute(
        """
        SELECT COUNT(*) FROM tasks t JOIN repositories r
          ON r.node_id=t.repository_id
        WHERE t.run_id=? AND t.stage='scan'
          AND json_extract(t.payload_json,'$.head_sha')<>r.head_sha
        """, (run_id,),
    ).fetchone()[0]
    renames = state.connection.execute(
        """
        SELECT COUNT(*) FROM tasks t JOIN repositories r
          ON r.node_id=t.repository_id
        WHERE t.run_id=? AND t.stage='scan'
          AND lower(json_extract(t.payload_json,'$.full_name'))<>lower(r.full_name)
        """, (run_id,),
    ).fetchone()[0]
    fresh = state.connection.execute(
        """
        SELECT task_key,status FROM tasks WHERE run_id=?
          AND stage='github-metadata-batch' AND task_key LIKE 'fresh:%'
        ORDER BY task_id
        """, (run_id,),
    ).fetchall()
    fresh_epochs = {str(row["task_key"]).split(":", 2)[1] for row in fresh}
    if len(fresh_epochs) != 1 or any(row["status"] != "complete" for row in fresh):
        raise PipelineError("privacy resume fresh metadata epoch changed")
    audit = _privacy_source_audit(
        repo_root, graphql["current_network_task_source_sha256"]
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state, run_id, control_stage=_PRIVACY_CONTROL_STAGE
        )
        control = {
            "version": 1, "kind": "phase8-privacy-resume-control",
            "policy": "purge-nonpublic-and-pin-surviving-scan-evidence",
            "predecessor_source_commit": audit["predecessor_source_commit"],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "graphql_resume_contract_sha256": graphql["contract_sha256"],
            "prior_scan_task_count": len(prior_rows),
            "current_scan_task_count": len(current_rows),
            "current_completed_scan_task_count": current_counts["complete"],
            "current_deferred_scan_task_count": current_counts["failed"],
            "purged_scan_task_count": len(missing_keys),
            "purged_completed_scan_task_count": missing_status["complete"],
            "purged_deferred_scan_task_count": missing_status["failed"],
            "purged_task_keys_sha256": _canonical_sha256(missing_keys),
            "purged_repository_nodes_sha256": _canonical_sha256(sorted(
                str(prior[key]["repository_id"]) for key in missing_keys
            )),
            "remaining_deferred_task_keys": remaining_keys,
            "remaining_deferred_task_keys_sha256": _canonical_sha256(
                remaining_keys
            ),
            "remaining_deferred_repository_proof_sha256": _canonical_sha256(
                proof_rows
            ),
            "scan_head_pin_count": int(head_pins),
            "scan_bound_rename_count": int(renames),
            "fresh_metadata_epoch": next(iter(fresh_epochs)),
            "fresh_metadata_batch_count": len(fresh),
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_scan_attempts": 0, "changed_scan_results": 0,
            "changed_citation_cache_entries": 0, "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["privacy_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract, mode="reconcile", wanted=selected,
            budgets=budgets, metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError("privacy resume reviewed contract changed")
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError("privacy resume run changed concurrently")
        state.update_stage(
            run_id, _PRIVACY_CONTROL_STAGE, status="complete",
            counters={
                "purged_scan_tasks": len(missing_keys),
                "remaining_scan_tasks": len(current_rows),
                "remaining_deferred_scan_tasks": len(remaining_keys),
                "scan_heads_to_pin": int(head_pins),
            },
            metrics={
                "new_scan_attempts": 0, "changed_scan_results": 0,
                "changed_citation_cache_entries": 0, "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state, run_id, control_stage=_PRIVACY_CONTROL_STAGE
        )
        if after != before:
            raise PipelineError("privacy resume changed preserved state")
    return {
        "run_id": run_id, "status": "failed", "control": control,
        "purged_scan_tasks": len(missing_keys),
        "remaining_scan_tasks": len(current_rows),
        "remaining_deferred_scan_tasks": len(remaining_keys),
        "launchd_armed": False,
    }


def authorize_phase8_fresh_candidate_deferral_control(
    *, state: StateDB, repo_root: Path, run_id: str, proof_path: Path,
) -> dict[str, Any]:
    """Defer only the reviewed post-refresh candidates lacking scan tasks."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "fresh-candidate deferral requires the failed reconcile run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        privacy = dict(contract["privacy_resume_control"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
        proof_document = json.loads(proof_path.read_text(encoding="utf-8"))
        proof = proof_document["tasks"]
    except (
        KeyError, TypeError, ValueError, OSError, json.JSONDecodeError
    ) as exc:
        raise PipelineError(
            "fresh-candidate deferral proof or run is malformed"
        ) from exc
    existing_control = contract.get("fresh_candidate_deferral_control")
    if (
        privacy.get("kind") != "phase8-privacy-resume-control"
        or (
            existing_control is None
            and privacy.get("current_network_task_source_sha256")
            != contract.get("network_task_source_sha256")
        )
        or (
            existing_control is not None
            and (
                _validate_phase8_fresh_candidate_deferral_control(
                    existing_control, privacy
                ).get("current_network_task_source_sha256")
                != contract.get("network_task_source_sha256")
                or _network_task_source_sha256()
                != contract.get("network_task_source_sha256")
            )
        )
        or fingerprints != current_fingerprints().as_dict()
        or proof_document.get("version") != 1
        or proof_document.get("kind")
        != "phase8-fresh-candidate-deferral-proof"
        or not isinstance(proof, list)
        or not proof
    ):
        raise PipelineError("fresh-candidate deferral identity changed")
    normalized = []
    for item in proof:
        if (
            not isinstance(item, dict)
            or set(item) != {
                "task_key", "repository_identity_sha256", "libraries"
            }
            or not isinstance(item.get("task_key"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["task_key"])
            or not isinstance(item.get("repository_identity_sha256"), str)
            or not re.fullmatch(
                r"[0-9a-f]{64}", item["repository_identity_sha256"]
            )
            or not isinstance(item.get("libraries"), list)
            or not item["libraries"]
            or item["libraries"] != sorted(set(item["libraries"]))
            or not set(item["libraries"]) <= selected
        ):
            raise PipelineError(
                "fresh-candidate deferral task proof is invalid"
            )
        normalized.append(dict(item))
    normalized.sort(key=lambda item: item["task_key"])
    if (
        proof != normalized
        or len({item["task_key"] for item in proof}) != len(proof)
        or len({item["repository_identity_sha256"] for item in proof})
        != len(proof)
    ):
        raise PipelineError(
            "fresh-candidate deferral task proof is not canonical"
        )
    identity_rows = {}
    for row in state.connection.execute(
        """
        SELECT r.node_id,r.full_name FROM repositories r
        WHERE NOT EXISTS (
            SELECT 1 FROM tasks t WHERE t.run_id=? AND t.stage='scan'
              AND t.repository_id=r.node_id
        )
        """,
        (run_id,),
    ):
        identity = hashlib.sha256(
            (str(row["node_id"]) + "\0" + str(row["full_name"])).encode(
                "utf-8"
            )
        ).hexdigest()
        identity_rows[identity] = row
    for item in proof:
        if item["repository_identity_sha256"] not in identity_rows:
            raise PipelineError(
                "fresh-candidate deferral repository proof changed"
            )
        existing = state.connection.execute(
            """
            SELECT 1 FROM tasks WHERE run_id=? AND stage='scan' AND task_key=?
            """,
            (run_id, item["task_key"]),
        ).fetchone()
        if existing is not None:
            raise PipelineError(
                "fresh-candidate deferral task entered the immutable universe"
            )
    counts = dict(state.connection.execute(
        """
        SELECT status,COUNT(*) FROM tasks WHERE run_id=? AND stage='scan'
        GROUP BY status
        """,
        (run_id,),
    ).fetchall())
    if (
        counts != {
            "complete": privacy["current_completed_scan_task_count"],
            "failed": privacy["current_deferred_scan_task_count"],
        }
        or sum(counts.values()) != privacy["current_scan_task_count"]
    ):
        raise PipelineError(
            "fresh-candidate deferral scan partition changed"
        )
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "fresh-candidate deferral found a changed safety budget"
        )
    if existing_control is None:
        audit = _fresh_candidate_source_audit(
            repo_root, privacy["current_network_task_source_sha256"]
        )
    else:
        audit = {
            field: existing_control[field]
            for field in (
                "predecessor_source_commit", "successor_source_commit",
                "changed_paths", "source_audit_sha256",
                "prior_network_task_source_sha256",
                "current_network_task_source_sha256",
            )
        }
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state, run_id, control_stage=_FRESH_CANDIDATE_CONTROL_STAGE
        )
        control = {
            "version": 1,
            "kind": "phase8-fresh-candidate-deferral-control",
            "policy": "owner-defer-unscanned-post-refresh-candidates",
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "privacy_resume_contract_sha256": privacy["contract_sha256"],
            "scan_task_universe_count": privacy["current_scan_task_count"],
            "completed_scan_task_count": privacy[
                "current_completed_scan_task_count"
            ],
            "owner_deferred_scan_task_count": privacy[
                "current_deferred_scan_task_count"
            ],
            "deferred_repository_count": len(proof),
            "deferred_task_proof": proof,
            "deferred_task_proof_sha256": _canonical_sha256(proof),
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["fresh_candidate_deferral_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "fresh-candidate deferral reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "fresh-candidate deferral run changed concurrently"
            )
        state.update_stage(
            run_id,
            _FRESH_CANDIDATE_CONTROL_STAGE,
            status="complete",
            counters={"deferred_repositories": len(proof)},
            metrics={
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state, run_id, control_stage=_FRESH_CANDIDATE_CONTROL_STAGE
        )
        if after != before:
            raise PipelineError(
                "fresh-candidate deferral changed preserved state"
            )
    note = state.path.parent / (
        "phase8-fresh-candidate-deferral-%s.json" % run_id
    )
    temporary = note.with_name(".%s.tmp-%d" % (note.name, os.getpid()))
    temporary.write_text(
        json.dumps({
            "version": 1,
            "kind": "phase8-fresh-candidate-deferral-note",
            "run_id": run_id,
            "control_sha256": control["contract_sha256"],
            "deferred_repository_count": len(proof),
            "tasks": proof,
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, note)
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "deferred_repository_count": len(proof),
        "note_path": str(note),
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_visibility_set_resume_control(
    *, state: StateDB, repo_root: Path, run_id: str,
) -> dict[str, Any]:
    """Adopt the failed-epoch supersession fix without changing evidence."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "visibility-set resume control requires the failed reconcile run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        fresh_candidate = _validate_phase8_fresh_candidate_deferral_control(
            contract["fresh_candidate_deferral_control"],
            contract["privacy_resume_control"],
        )
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility-set resume run contract is malformed"
        ) from exc
    if (
        contract.get("visibility_set_resume_control") is not None
        or fresh_candidate["current_network_task_source_sha256"]
        != contract.get("network_task_source_sha256")
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError("visibility-set resume run identity changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "visibility-set resume found a changed safety budget"
        )
    stages = {
        row["stage"]: row["status"]
        for row in state.connection.execute(
            "SELECT stage,status FROM stages WHERE run_id=?", (run_id,)
        )
    }
    if (
        stages.get("citations") != "complete"
        or stages.get("final_visibility") != "failed"
        or stages.get("publication") != "failed"
    ):
        raise PipelineError(
            "visibility-set resume requires the exact post-citation failure"
        )

    fresh_rows = state.connection.execute(
        """
        SELECT task_key,status FROM tasks WHERE run_id=?
          AND stage='github-metadata-batch' AND task_key LIKE 'fresh:%'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    if not fresh_rows:
        raise PipelineError(
            "visibility-set resume has no fresh metadata epoch"
        )
    fresh_epoch = str(fresh_rows[-1]["task_key"]).split(":", 2)[1]
    newest_fresh_rows = [
        row for row in fresh_rows
        if str(row["task_key"]).split(":", 2)[1] == fresh_epoch
    ]
    if (
        not re.fullmatch(r"[0-9a-f]{16}", fresh_epoch)
        or any(row["status"] != "complete" for row in newest_fresh_rows)
    ):
        raise PipelineError(
            "visibility-set resume fresh metadata epoch changed"
        )

    visibility_rows = state.connection.execute(
        """
        SELECT task_key,status,payload_json FROM tasks WHERE run_id=?
          AND stage='github-final-visibility-batch' ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    visibility_epochs: set[str] = set()
    visibility_sets: set[str] = set()
    visibility_counts = {"complete": 0, "pending": 0}
    try:
        for row in visibility_rows:
            payload = json.loads(row["payload_json"])
            visibility_epochs.add(str(payload["epoch"]))
            visibility_sets.add(str(payload["set_sha256"]))
            visibility_counts[str(row["status"])] += 1
    except (
        KeyError, TypeError, ValueError, json.JSONDecodeError
    ) as exc:
        raise PipelineError(
            "visibility-set resume prior epoch is malformed"
        ) from exc
    if (
        len(visibility_epochs) != 1
        or len(visibility_sets) != 1
        or not visibility_rows
        or visibility_counts["complete"] < 1
        or visibility_counts["pending"] < 1
    ):
        raise PipelineError(
            "visibility-set resume prior epoch changed"
        )
    prior_epoch = next(iter(visibility_epochs))
    prior_set = next(iter(visibility_sets))
    if (
        not re.fullmatch(r"[0-9a-f]{32}", prior_epoch)
        or not re.fullmatch(r"[0-9a-f]{64}", prior_set)
    ):
        raise PipelineError(
            "visibility-set resume prior epoch identity changed"
        )

    audit = _visibility_set_source_audit(
        repo_root,
        fresh_candidate["current_network_task_source_sha256"],
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state, run_id, control_stage=_VISIBILITY_SET_CONTROL_STAGE
        )
        control = {
            "version": 1,
            "kind": "phase8-visibility-set-resume-control",
            "policy": (
                "supersede-failed-visibility-epoch-after-fresh-metadata"
            ),
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "fresh_candidate_deferral_contract_sha256": fresh_candidate[
                "contract_sha256"
            ],
            "fresh_metadata_epoch": fresh_epoch,
            "fresh_metadata_batch_count": len(newest_fresh_rows),
            "prior_visibility_epoch": prior_epoch,
            "prior_visibility_set_sha256": prior_set,
            "prior_visibility_task_count": len(visibility_rows),
            "prior_visibility_completed_task_count": visibility_counts[
                "complete"
            ],
            "prior_visibility_pending_task_count": visibility_counts[
                "pending"
            ],
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["visibility_set_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "visibility-set resume reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "visibility-set resume run changed concurrently"
            )
        state.update_stage(
            run_id,
            _VISIBILITY_SET_CONTROL_STAGE,
            status="complete",
            counters={
                "fresh_metadata_batches": len(newest_fresh_rows),
                "prior_visibility_tasks": len(visibility_rows),
                "prior_visibility_complete": visibility_counts["complete"],
                "prior_visibility_pending": visibility_counts["pending"],
            },
            metrics={
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state, run_id, control_stage=_VISIBILITY_SET_CONTROL_STAGE
        )
        if after != before:
            raise PipelineError(
                "visibility-set resume changed preserved state"
            )
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "fresh_metadata_batches": len(newest_fresh_rows),
        "prior_visibility_tasks": len(visibility_rows),
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_visibility_rejection_resume_control(
    *, state: StateDB, repo_root: Path, run_id: str,
) -> dict[str, Any]:
    """Authorize fresh metadata for one missing node in the newest epoch."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "visibility-rejection resume requires the failed reconcile run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        visibility_set = _validate_phase8_visibility_set_resume_control(
            contract["visibility_set_resume_control"],
            contract["fresh_candidate_deferral_control"],
        )
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility-rejection resume run contract is malformed"
        ) from exc
    if (
        contract.get("visibility_rejection_resume_control") is not None
        or visibility_set["current_network_task_source_sha256"]
        != contract.get("network_task_source_sha256")
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError(
            "visibility-rejection resume run identity changed"
        )
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "visibility-rejection resume found a changed safety budget"
        )
    stages = {
        row["stage"]: row["status"]
        for row in state.connection.execute(
            "SELECT stage,status FROM stages WHERE run_id=?", (run_id,)
        )
    }
    if (
        stages.get("citations") != "complete"
        or stages.get("final_visibility") != "failed"
        or stages.get("publication") != "failed"
    ):
        raise PipelineError(
            "visibility-rejection resume requires the exact failed boundary"
        )

    visibility_tasks = state.connection.execute(
        """
        SELECT task_id,task_key,status,payload_json,result_json,
               lease_owner,lease_expires_at,error_code
        FROM tasks WHERE run_id=?
          AND stage='github-final-visibility-batch'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    if not visibility_tasks:
        raise PipelineError(
            "visibility-rejection resume has no visibility tasks"
        )
    try:
        newest_epoch = str(json.loads(
            visibility_tasks[-1]["payload_json"] or "{}"
        )["epoch"])
        newest_tasks = [
            task for task in visibility_tasks
            if str(json.loads(task["payload_json"] or "{}")["epoch"])
            == newest_epoch
        ]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility-rejection resume task payload is malformed"
        ) from exc
    status_counts: dict[str, int] = {}
    invalid: list[tuple[Any, dict[str, Any]]] = []
    for task in newest_tasks:
        status = str(task["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
        if status != "complete":
            if (
                status != "pending"
                or task["result_json"] is not None
                or task["lease_owner"] is not None
                or task["lease_expires_at"] is not None
                or task["error_code"] is not None
            ):
                raise PipelineError(
                    "visibility-rejection pending task shape changed"
                )
            continue
        try:
            repositories = json.loads(
                task["result_json"] or "{}"
            )["repositories"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "visibility-rejection result is malformed"
            ) from exc
        if not isinstance(repositories, list):
            raise PipelineError("visibility-rejection result is malformed")
        for repository in repositories:
            if not isinstance(repository, dict):
                raise PipelineError(
                    "visibility-rejection result is malformed"
                )
            public = (
                repository.get("admitted_public") is True
                and repository.get("status") == "ok"
                and repository.get("node_id")
                == repository.get("requested_node_id")
                and repository.get("requested_full_name") is None
                and repository.get("is_fork") is False
                and repository.get("is_archived") is False
            )
            if not public:
                invalid.append((task, repository))
    if (
        not re.fullmatch(r"[0-9a-f]{32}", newest_epoch)
        or newest_epoch == visibility_set["prior_visibility_epoch"]
        or set(status_counts) != {"complete", "pending"}
        or status_counts["complete"] < 1
        or status_counts["pending"] < 1
        or len(invalid) != 1
    ):
        raise PipelineError(
            "visibility-rejection newest incident set changed"
        )
    failed_task, missing = invalid[0]
    node_id = missing.get("requested_node_id")
    if (
        not isinstance(node_id, str)
        or not node_id
        or missing.get("request_key") != "node:" + node_id
        or missing.get("admitted_public") is not False
        or missing.get("status") != "missing"
        or missing.get("node_id") is not None
        or missing.get("full_name") is not None
        or missing.get("requested_full_name") is not None
        or missing.get("is_fork") is not None
        or missing.get("is_archived") is not None
        or missing.get("error_count") != 0
    ):
        raise PipelineError(
            "visibility-rejection missing-node proof changed"
        )

    audit = _visibility_rejection_source_audit(
        repo_root,
        visibility_set["current_network_task_source_sha256"],
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_REJECTION_CONTROL_STAGE,
        )
        control = {
            "version": 1,
            "kind": "phase8-visibility-rejection-resume-control",
            "policy": "force-fresh-metadata-after-newest-missing-node",
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "visibility_set_resume_contract_sha256": visibility_set[
                "contract_sha256"
            ],
            "visibility_epoch": newest_epoch,
            "failed_visibility_task_key": str(failed_task["task_key"]),
            "missing_repository_node_sha256": hashlib.sha256(
                node_id.encode("utf-8")
            ).hexdigest(),
            "visibility_batch_count": len(newest_tasks),
            "completed_visibility_batch_count": status_counts["complete"],
            "pending_visibility_batch_count": status_counts["pending"],
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract[
            "visibility_rejection_resume_control"
        ] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "visibility-rejection reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "visibility-rejection run changed concurrently"
            )
        state.update_stage(
            run_id,
            _VISIBILITY_REJECTION_CONTROL_STAGE,
            status="complete",
            counters={
                "visibility_batches": len(newest_tasks),
                "completed_visibility_batches": status_counts["complete"],
                "pending_visibility_batches": status_counts["pending"],
                "missing_repositories": 1,
            },
            metrics={
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_REJECTION_CONTROL_STAGE,
        )
        if after != before:
            raise PipelineError(
                "visibility-rejection resume changed preserved state"
            )
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "visibility_batches": len(newest_tasks),
        "completed_visibility_batches": status_counts["complete"],
        "pending_visibility_batches": status_counts["pending"],
        "missing_repositories": 1,
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_visibility_refresh_resume_control(
    *, state: StateDB, repo_root: Path, run_id: str,
) -> dict[str, Any]:
    """Authorize a new refresh after the old partial epoch collided."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "visibility-refresh resume requires the failed reconcile run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        visibility_set = _validate_phase8_visibility_set_resume_control(
            contract["visibility_set_resume_control"],
            contract["fresh_candidate_deferral_control"],
        )
        rejection = _validate_phase8_visibility_rejection_resume_control(
            contract["visibility_rejection_resume_control"],
            visibility_set,
        )
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility-refresh resume run contract is malformed"
        ) from exc
    if (
        contract.get("visibility_refresh_resume_control") is not None
        or rejection["current_network_task_source_sha256"]
        != contract.get("network_task_source_sha256")
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError("visibility-refresh resume run identity changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "visibility-refresh resume found a changed safety budget"
        )
    stages = {
        row["stage"]: row["status"]
        for row in state.connection.execute(
            "SELECT stage,status FROM stages WHERE run_id=?", (run_id,)
        )
    }
    if (
        stages.get("metadata") != "failed"
        or stages.get("final_visibility") != "failed"
        or stages.get("publication") != "failed"
    ):
        raise PipelineError(
            "visibility-refresh resume requires the exact metadata failure"
        )
    rejection_stage = state.connection.execute(
        """
        SELECT finished_at FROM stages WHERE run_id=? AND stage=?
        """,
        (run_id, _VISIBILITY_REJECTION_CONTROL_STAGE),
    ).fetchone()
    if rejection_stage is None or rejection_stage["finished_at"] is None:
        raise PipelineError(
            "visibility-refresh resume has no rejection boundary"
        )
    fresh_rows = state.connection.execute(
        """
        SELECT task_id,task_key,status,payload_json,result_json,attempts,
               lease_owner,lease_expires_at,error_code,created_at
        FROM tasks WHERE run_id=? AND stage='github-metadata-batch'
          AND task_key LIKE 'fresh:%' ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    epochs: set[str] = set()
    completed = []
    pending = []
    try:
        for row in fresh_rows:
            epoch = str(row["task_key"]).split(":", 2)[1]
            epochs.add(epoch)
            if row["status"] == "complete":
                completed.append(row)
            elif row["status"] == "pending":
                pending.append(row)
            else:
                raise PipelineError(
                    "visibility-refresh fresh task status changed"
                )
    except (IndexError, TypeError) as exc:
        raise PipelineError(
            "visibility-refresh fresh task identity changed"
        ) from exc
    pending_ids = [int(row["task_id"]) for row in pending]
    placeholders = ",".join("?" for _ in pending_ids)
    pending_usage = (
        state.connection.execute(
            "SELECT COUNT(*) FROM network_task_usage WHERE task_id IN (%s)"
            % placeholders,
            tuple(pending_ids),
        ).fetchone()[0]
        if pending_ids
        else 0
    )
    if (
        epochs != {visibility_set["fresh_metadata_epoch"]}
        or len(completed) != visibility_set["fresh_metadata_batch_count"]
        or len(pending) != len(completed)
        or not pending
        or pending_usage != 0
        or any(
            row["result_json"] is not None
            or row["attempts"] != 0
            or row["lease_owner"] is not None
            or row["lease_expires_at"] is not None
            or row["error_code"] is not None
            or row["created_at"] <= rejection_stage["finished_at"]
            for row in pending
        )
        or set(row["task_key"] for row in completed)
        & set(row["task_key"] for row in pending)
    ):
        raise PipelineError(
            "visibility-refresh collision task set changed"
        )
    collision_proof = [{
        "task_key": str(row["task_key"]),
        "payload_sha256": hashlib.sha256(
            str(row["payload_json"]).encode("utf-8")
        ).hexdigest(),
    } for row in pending]
    collision_sha256 = _canonical_sha256(collision_proof)

    audit = _visibility_refresh_source_audit(
        repo_root,
        rejection["current_network_task_source_sha256"],
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_REFRESH_CONTROL_STAGE,
        )
        control = {
            "version": 1,
            "kind": "phase8-visibility-refresh-resume-control",
            "policy": "new-refresh-never-resumes-prior-partial-epoch",
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "visibility_rejection_resume_contract_sha256": rejection[
                "contract_sha256"
            ],
            "prior_fresh_metadata_epoch": visibility_set[
                "fresh_metadata_epoch"
            ],
            "prior_completed_fresh_metadata_batch_count": len(completed),
            "collision_pending_fresh_metadata_batch_count": len(pending),
            "collision_fresh_metadata_task_set_sha256": collision_sha256,
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["visibility_refresh_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected,
            budgets=budgets,
            metadata_batch_size=metadata_batch_size,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "visibility-refresh reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "visibility-refresh run changed concurrently"
            )
        state.update_stage(
            run_id,
            _VISIBILITY_REFRESH_CONTROL_STAGE,
            status="complete",
            counters={
                "prior_fresh_metadata_batches": len(completed),
                "collision_pending_fresh_metadata_batches": len(pending),
            },
            metrics={
                "new_metadata_request_count": 0,
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_REFRESH_CONTROL_STAGE,
        )
        if after != before:
            raise PipelineError(
                "visibility-refresh resume changed preserved state"
            )
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "prior_fresh_metadata_batches": len(completed),
        "collision_pending_fresh_metadata_batches": len(pending),
        "new_metadata_request_count": 0,
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_visibility_budget_resume_control(
    *, state: StateDB, repo_root: Path, run_id: str,
) -> dict[str, Any]:
    """Authorize 100-lookup cohort batches under the unchanged point cap."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "visibility-budget resume requires the failed reconcile run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        rejection = _validate_phase8_visibility_rejection_resume_control(
            contract["visibility_rejection_resume_control"],
            _validate_phase8_visibility_set_resume_control(
                contract["visibility_set_resume_control"],
                contract["fresh_candidate_deferral_control"],
            ),
        )
        refresh = _validate_phase8_visibility_refresh_resume_control(
            contract["visibility_refresh_resume_control"], rejection
        )
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility-budget resume run contract is malformed"
        ) from exc
    if (
        contract.get("visibility_budget_resume_control") is not None
        or refresh["current_network_task_source_sha256"]
        != contract.get("network_task_source_sha256")
        or contract.get("metadata_batch_size") != 50
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError("visibility-budget resume run identity changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "visibility-budget resume found a changed safety budget"
        )
    stages = {
        row["stage"]: row["status"]
        for row in state.connection.execute(
            "SELECT stage,status FROM stages WHERE run_id=?", (run_id,)
        )
    }
    if (
        stages.get("metadata") != "failed"
        or stages.get("final_visibility") != "failed"
        or stages.get("publication") != "failed"
        or stages.get(_VISIBILITY_REFRESH_CONTROL_STAGE) != "complete"
    ):
        raise PipelineError(
            "visibility-budget resume requires the exact refresh boundary"
        )
    collision_rows = state.connection.execute(
        """
        SELECT task_key,payload_json,status,attempts,result_json,lease_owner,
               lease_expires_at,error_code
        FROM tasks WHERE run_id=? AND stage='github-metadata-batch'
          AND task_key LIKE 'fresh:%' AND status='pending'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    if len(collision_rows) != refresh[
        "collision_pending_fresh_metadata_batch_count"
    ]:
        raise PipelineError(
            "visibility-budget pending metadata task set changed"
        )
    lookup_count = 0
    lookup_keys: set[str] = set()
    try:
        for row in collision_rows:
            payload = json.loads(row["payload_json"] or "{}")
            lookups = payload["lookups"]
            if (
                not isinstance(lookups, list)
                or not 1 <= len(lookups) <= 50
                or row["attempts"] != 0
                or row["result_json"] is not None
                or row["lease_owner"] is not None
                or row["lease_expires_at"] is not None
                or row["error_code"] is not None
            ):
                raise ValueError("invalid pending metadata batch")
            for lookup in lookups:
                if not isinstance(lookup, dict):
                    raise ValueError("invalid metadata lookup")
                key = canonical_json(lookup)
                if key in lookup_keys:
                    raise ValueError("duplicate metadata lookup")
                lookup_keys.add(key)
            lookup_count += len(lookups)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility-budget metadata lookup proof changed"
        ) from exc
    final_batches = int(rejection["visibility_batch_count"])
    journal = _graphql_journal_budget(state, run_id)
    journaled_points = int(journal["points_used"])
    planned_metadata_batches = (lookup_count + 99) // 100
    projected_points = (
        journaled_points + planned_metadata_batches + final_batches
    )
    if (
        lookup_count < 1
        or journaled_points < 0
        or projected_points > budgets.max_graphql_points
    ):
        raise PipelineError(
            "visibility-budget plan does not fit the unchanged point cap"
        )
    audit = _visibility_budget_source_audit(
        repo_root, refresh["current_network_task_source_sha256"]
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_BUDGET_CONTROL_STAGE,
        )
        control = {
            "version": 1,
            "kind": "phase8-visibility-budget-resume-control",
            "policy": (
                "cohort-only-100-lookup-batches-with-unchanged-budget"
            ),
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "visibility_refresh_resume_contract_sha256": refresh[
                "contract_sha256"
            ],
            "prior_metadata_batch_size": 50,
            "current_metadata_batch_size": 100,
            "metadata_lookup_count": lookup_count,
            "planned_metadata_batch_count": planned_metadata_batches,
            "planned_final_visibility_batch_count": final_batches,
            "journaled_graphql_points": journaled_points,
            "remaining_graphql_point_budget": (
                budgets.max_graphql_points - journaled_points
            ),
            "projected_unit_cost_graphql_points": projected_points,
            "max_graphql_points": budgets.max_graphql_points,
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["metadata_batch_size"] = 100
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["visibility_budget_resume_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract,
            mode="reconcile",
            wanted=selected,
            budgets=budgets,
            metadata_batch_size=100,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "visibility-budget reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "visibility-budget run changed concurrently"
            )
        state.update_stage(
            run_id,
            _VISIBILITY_BUDGET_CONTROL_STAGE,
            status="complete",
            counters={
                "metadata_lookups": lookup_count,
                "planned_metadata_batches": planned_metadata_batches,
                "planned_final_visibility_batches": final_batches,
            },
            metrics={
                "journaled_graphql_points": journaled_points,
                "projected_unit_cost_graphql_points": projected_points,
                "max_graphql_points": budgets.max_graphql_points,
                "new_metadata_request_count": 0,
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_BUDGET_CONTROL_STAGE,
        )
        if after != before:
            raise PipelineError(
                "visibility-budget resume changed preserved state"
            )
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "metadata_lookups": lookup_count,
        "planned_metadata_batches": planned_metadata_batches,
        "planned_final_visibility_batches": final_batches,
        "journaled_graphql_points": journaled_points,
        "projected_unit_cost_graphql_points": projected_points,
        "max_graphql_points": budgets.max_graphql_points,
        "new_metadata_request_count": 0,
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_visibility_transport_retry_control(
    *, state: StateDB, repo_root: Path, run_id: str,
) -> dict[str, Any]:
    """Reserve one point for one malformed GraphQL response before retry."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "visibility transport retry requires the failed reconcile run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        visibility_set = _validate_phase8_visibility_set_resume_control(
            contract["visibility_set_resume_control"],
            contract["fresh_candidate_deferral_control"],
        )
        rejection = _validate_phase8_visibility_rejection_resume_control(
            contract["visibility_rejection_resume_control"], visibility_set
        )
        refresh = _validate_phase8_visibility_refresh_resume_control(
            contract["visibility_refresh_resume_control"], rejection
        )
        budget_control = _validate_phase8_visibility_budget_resume_control(
            contract["visibility_budget_resume_control"], refresh
        )
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility transport retry run contract is malformed"
        ) from exc
    if (
        contract.get("visibility_transport_retry_control") is not None
        or budget_control["current_network_task_source_sha256"]
        != contract.get("network_task_source_sha256")
        or contract.get("metadata_batch_size") != 100
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError(
            "visibility transport retry run identity changed"
        )
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "visibility transport retry found a changed safety budget"
        )
    stages = {
        row["stage"]: row["status"]
        for row in state.connection.execute(
            "SELECT stage,status FROM stages WHERE run_id=?", (run_id,)
        )
    }
    if (
        stages.get("metadata") != "failed"
        or stages.get("final_visibility") != "failed"
        or stages.get("publication") != "failed"
        or stages.get(_VISIBILITY_BUDGET_CONTROL_STAGE) != "complete"
    ):
        raise PipelineError(
            "visibility transport retry requires the exact metadata failure"
        )
    rows = state.connection.execute(
        """
        SELECT task_id,task_key,status,attempts,max_attempts,error_code,
               result_json,lease_owner,lease_expires_at
        FROM tasks WHERE run_id=? AND stage='github-metadata-batch'
          AND task_id>=? ORDER BY task_id
        """,
        (run_id, 413741),
    ).fetchall()
    completed = [row for row in rows if row["status"] == "complete"]
    pending = [row for row in rows if row["status"] == "pending"]
    failed = [
        row for row in pending
        if row["attempts"] or row["error_code"] is not None
    ]
    if (
        len(rows) != budget_control["planned_metadata_batch_count"]
        or len(completed) != 189
        or len(pending) != len(rows) - len(completed)
        or len(failed) != 1
    ):
        raise PipelineError(
            "visibility transport retry task partition changed"
        )
    retry = failed[0]
    try:
        epoch = str(retry["task_key"]).split(":", 2)[1]
    except (IndexError, TypeError) as exc:
        raise PipelineError(
            "visibility transport retry task identity changed"
        ) from exc
    if (
        not re.fullmatch(r"[0-9a-f]{16}", epoch)
        or retry["attempts"] != 1
        or retry["max_attempts"] != 3
        or retry["error_code"] != "github-metadata-batch-failed"
        or retry["result_json"] is not None
        or retry["lease_owner"] is not None
        or retry["lease_expires_at"] is not None
        or any(
            row["attempts"] != 0 or row["error_code"] is not None
            for row in pending if row["task_id"] != retry["task_id"]
        )
        or state.connection.execute(
            "SELECT COUNT(*) FROM network_task_usage WHERE task_id=?",
            (retry["task_id"],),
        ).fetchone()[0] != 0
    ):
        raise PipelineError(
            "visibility transport retry attempt proof changed"
        )
    journaled = int(_graphql_journal_budget(state, run_id)["points_used"])
    projected = int(
        budget_control["projected_unit_cost_graphql_points"]
    ) + 1
    if projected > budgets.max_graphql_points:
        raise PipelineError(
            "visibility transport retry reserve exceeds the point cap"
        )
    audit = _visibility_transport_retry_source_audit(
        repo_root, budget_control["current_network_task_source_sha256"]
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_TRANSPORT_RETRY_CONTROL_STAGE,
        )
        control = {
            "version": 1,
            "kind": "phase8-visibility-transport-retry-control",
            "policy": (
                "reserve-one-point-for-one-malformed-graphql-response"
            ),
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "visibility_budget_resume_contract_sha256": budget_control[
                "contract_sha256"
            ],
            "retry_task_id": int(retry["task_id"]),
            "retry_task_key_sha256": hashlib.sha256(
                str(retry["task_key"]).encode("utf-8")
            ).hexdigest(),
            "retry_metadata_epoch": epoch,
            "completed_new_metadata_batch_count": len(completed),
            "pending_new_metadata_batch_count": len(pending),
            "failed_attempt_count": 1,
            "reserved_unobserved_points": 1,
            "journaled_observed_points": journaled,
            "projected_graphql_points_with_reserve": projected,
            "max_graphql_points": budgets.max_graphql_points,
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["visibility_transport_retry_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract, mode="reconcile", wanted=selected,
            budgets=budgets, metadata_batch_size=100,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "visibility transport retry reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "visibility transport retry run changed concurrently"
            )
        state.update_stage(
            run_id,
            _VISIBILITY_TRANSPORT_RETRY_CONTROL_STAGE,
            status="complete",
            counters={
                "completed_new_metadata_batches": len(completed),
                "pending_new_metadata_batches": len(pending),
                "failed_attempts_reserved": 1,
            },
            metrics={
                "journaled_observed_points": journaled,
                "reserved_unobserved_points": 1,
                "projected_graphql_points_with_reserve": projected,
                "max_graphql_points": budgets.max_graphql_points,
                "new_metadata_request_count": 0,
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state,
            run_id,
            control_stage=_VISIBILITY_TRANSPORT_RETRY_CONTROL_STAGE,
        )
        if after != before:
            raise PipelineError(
                "visibility transport retry changed preserved state"
            )
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "completed_new_metadata_batches": len(completed),
        "pending_new_metadata_batches": len(pending),
        "failed_attempts_reserved": 1,
        "journaled_observed_points": journaled,
        "reserved_unobserved_points": 1,
        "projected_graphql_points_with_reserve": projected,
        "max_graphql_points": budgets.max_graphql_points,
        "new_metadata_request_count": 0,
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_visibility_epoch_recovery_control(
    *, state: StateDB, repo_root: Path, run_id: str,
    reference_state_path: Path,
) -> dict[str, Any]:
    """Restore only the certified pending rows and select their exact epoch."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "visibility epoch recovery requires the failed reconcile run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        visibility_set = _validate_phase8_visibility_set_resume_control(
            contract["visibility_set_resume_control"],
            contract["fresh_candidate_deferral_control"],
        )
        rejection = _validate_phase8_visibility_rejection_resume_control(
            contract["visibility_rejection_resume_control"], visibility_set
        )
        refresh = _validate_phase8_visibility_refresh_resume_control(
            contract["visibility_refresh_resume_control"], rejection
        )
        budget_control = _validate_phase8_visibility_budget_resume_control(
            contract["visibility_budget_resume_control"], refresh
        )
        transport = _validate_phase8_visibility_transport_retry_control(
            contract["visibility_transport_retry_control"], budget_control
        )
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "visibility epoch recovery run contract is malformed"
        ) from exc
    if (
        contract.get("visibility_epoch_recovery_control") is not None
        or transport["current_network_task_source_sha256"]
        != contract.get("network_task_source_sha256")
        or contract.get("metadata_batch_size") != 100
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError("visibility epoch recovery run identity changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "visibility epoch recovery found a changed safety budget"
        )
    reference_path = reference_state_path.resolve()
    if reference_path == state.path.resolve() or not reference_path.is_file():
        raise PipelineError(
            "visibility epoch recovery reference is absent or live"
        )
    uri = "file:%s?mode=ro&immutable=1" % reference_path.as_posix()
    reference = sqlite3.connect(uri, uri=True)
    reference.row_factory = sqlite3.Row
    resume_epoch = transport["retry_metadata_epoch"]
    try:
        if reference.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise PipelineError(
                "visibility epoch recovery reference failed quick_check"
            )
        reference_plan = json.loads(reference.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()["plan_json"])["execution_contract"]
        if (
            reference_plan["visibility_budget_resume_control"][
                "contract_sha256"
            ] != budget_control["contract_sha256"]
            or reference_plan.get("visibility_transport_retry_control")
            is not None
        ):
            raise PipelineError(
                "visibility epoch recovery reference contract changed"
            )
        sql = """
            SELECT * FROM tasks WHERE run_id=?
              AND stage='github-metadata-batch'
              AND task_key LIKE ? ORDER BY task_id
        """
        reference_rows = list(reference.execute(
            sql, (run_id, "fresh:" + resume_epoch + ":%")
        ))
        live_rows = list(state.connection.execute(
            sql, (run_id, "fresh:" + resume_epoch + ":%")
        ))
        if len(reference_rows) != 388 or len(live_rows) != 388:
            raise PipelineError(
                "visibility epoch recovery resume task set changed"
            )
        columns = [row[1] for row in reference.execute("PRAGMA table_info(tasks)")]
        mutable = {
            "result_json", "status", "attempts", "lease_owner",
            "lease_expires_at", "available_at", "error_code", "updated_at",
            "finished_at",
        }
        restore_rows = []
        completed = 0
        for live, baseline_row in zip(live_rows, reference_rows):
            if live["task_id"] != baseline_row["task_id"] or any(
                live[column] != baseline_row[column]
                for column in columns if column not in mutable
            ):
                raise PipelineError(
                    "visibility epoch recovery immutable task changed"
                )
            if baseline_row["status"] == "complete":
                completed += 1
                if any(live[column] != baseline_row[column] for column in columns):
                    raise PipelineError(
                        "visibility epoch recovery completed evidence changed"
                    )
            elif baseline_row["status"] == "pending":
                if (
                    live["status"] != "complete"
                    or json.loads(live["result_json"] or "{}")
                    != {
                        "reason": "github-metadata-plan-updated",
                        "superseded": True,
                    }
                ):
                    raise PipelineError(
                        "visibility epoch recovery supersession changed"
                    )
                restore_rows.append(tuple(
                    baseline_row[column] for column in (
                        "result_json", "status", "attempts", "lease_owner",
                        "lease_expires_at", "available_at", "error_code",
                        "updated_at", "finished_at", "task_id",
                    )
                ))
            else:
                raise PipelineError(
                    "visibility epoch recovery reference status changed"
                )
        if completed != 189 or len(restore_rows) != 199:
            raise PipelineError(
                "visibility epoch recovery reference partition changed"
            )
    finally:
        reference.close()

    epoch_rows = list(state.connection.execute(
        """
        SELECT * FROM tasks WHERE run_id=? AND stage='github-metadata-batch'
          AND task_key LIKE 'fresh:%' ORDER BY task_id
        """,
        (run_id,),
    ))
    replacement_epochs = []
    for row in epoch_rows:
        epoch = str(row["task_key"]).split(":", 2)[1]
        if epoch != resume_epoch and epoch not in {"28af89c523454858"}:
            replacement_epochs.append(epoch)
    replacement_set = sorted(set(replacement_epochs))
    if len(replacement_set) != 1:
        raise PipelineError(
            "visibility epoch recovery replacement epoch changed"
        )
    replacement_epoch = replacement_set[0]
    replacement_rows = [
        row for row in epoch_rows
        if str(row["task_key"]).split(":", 2)[1] == replacement_epoch
    ]
    replacement_completed = [
        row for row in replacement_rows if row["status"] == "complete"
    ]
    replacement_pending = [
        row for row in replacement_rows if row["status"] == "pending"
    ]
    interrupted = [
        row for row in replacement_pending
        if row["attempts"] or row["error_code"] is not None
    ]
    if (
        len(replacement_completed) != 10
        or len(replacement_pending) != 378
        or len(interrupted) != 1
        or interrupted[0]["attempts"] != 1
        or interrupted[0]["error_code"] != "github-metadata-batch-failed"
    ):
        raise PipelineError(
            "visibility epoch recovery replacement partition changed"
        )
    restored_proof = [{
        "task_id": row[-1],
        "status": row[1],
        "attempts": row[2],
        "error_code": row[6],
    } for row in restore_rows]
    replacement_proof = [{
        "task_id": int(row["task_id"]),
        "task_key_sha256": hashlib.sha256(
            str(row["task_key"]).encode("utf-8")
        ).hexdigest(),
        "status": str(row["status"]),
        "attempts": int(row["attempts"]),
        "result_sha256": (
            hashlib.sha256(str(row["result_json"]).encode("utf-8")).hexdigest()
            if row["result_json"] is not None else None
        ),
    } for row in replacement_rows]
    journaled = int(_graphql_journal_budget(state, run_id)["points_used"])
    projected = 2483
    if journaled != 1992 or projected > budgets.max_graphql_points:
        raise PipelineError(
            "visibility epoch recovery GraphQL accounting changed"
        )
    audit = _visibility_epoch_recovery_source_audit(
        repo_root, transport["current_network_task_source_sha256"]
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state, run_id,
            control_stage=_VISIBILITY_EPOCH_RECOVERY_CONTROL_STAGE,
        )
        preserved_non_tasks = {
            key: value for key, value in before.items()
            if key not in {"tasks", "snapshot_sha256"}
        }
        state.connection.executemany(
            """
            UPDATE tasks SET result_json=?,status=?,attempts=?,lease_owner=?,
                lease_expires_at=?,available_at=?,error_code=?,updated_at=?,
                finished_at=? WHERE task_id=?
            """,
            restore_rows,
        )
        control = {
            "version": 1,
            "kind": "phase8-visibility-epoch-recovery-control",
            "policy": (
                "restore-certified-current-epoch-and-retain-replacement-evidence"
            ),
            "predecessor_source_commit": audit["predecessor_source_commit"],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "visibility_transport_retry_contract_sha256": transport[
                "contract_sha256"
            ],
            "reference_state_name": reference_path.name,
            "resume_metadata_epoch": resume_epoch,
            "replacement_metadata_epoch": replacement_epoch,
            "resume_epoch_batch_count": 388,
            "resume_epoch_completed_batch_count": completed,
            "restored_pending_batch_count": len(restore_rows),
            "replacement_completed_batch_count": len(replacement_completed),
            "replacement_pending_batch_count": len(replacement_pending),
            "additional_failed_attempt_count": 1,
            "additional_reserved_unobserved_points": 1,
            "total_reserved_unobserved_points": 2,
            "journaled_points_before_reserve": journaled,
            "projected_graphql_points_with_reserves": projected,
            "max_graphql_points": budgets.max_graphql_points,
            "restored_task_rows_sha256": _canonical_sha256(restored_proof),
            "replacement_task_rows_sha256": _canonical_sha256(
                replacement_proof
            ),
            "preserved_non_task_state_sha256": _canonical_sha256(
                preserved_non_tasks
            ),
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["visibility_epoch_recovery_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract, mode="reconcile", wanted=selected,
            budgets=budgets, metadata_batch_size=100,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "visibility epoch recovery reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "visibility epoch recovery run changed concurrently"
            )
        state.update_stage(
            run_id, _VISIBILITY_EPOCH_RECOVERY_CONTROL_STAGE,
            status="complete",
            counters={
                "resume_completed_batches": completed,
                "restored_pending_batches": len(restore_rows),
                "replacement_completed_batches": len(replacement_completed),
                "replacement_pending_batches": len(replacement_pending),
            },
            metrics={
                "journaled_points_before_reserve": journaled,
                "total_reserved_unobserved_points": 2,
                "projected_graphql_points_with_reserves": projected,
                "max_graphql_points": budgets.max_graphql_points,
                "new_metadata_request_count": 0,
                "new_scan_attempts": 0,
                "changed_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state, run_id,
            control_stage=_VISIBILITY_EPOCH_RECOVERY_CONTROL_STAGE,
        )
        after_non_tasks = {
            key: value for key, value in after.items()
            if key not in {"tasks", "snapshot_sha256"}
        }
        if after_non_tasks != preserved_non_tasks:
            raise PipelineError(
                "visibility epoch recovery changed non-task state"
            )
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "resume_completed_batches": completed,
        "restored_pending_batches": len(restore_rows),
        "replacement_completed_batches": len(replacement_completed),
        "replacement_pending_batches": len(replacement_pending),
        "journaled_points_before_reserve": journaled,
        "total_reserved_unobserved_points": 2,
        "projected_graphql_points_with_reserves": projected,
        "max_graphql_points": budgets.max_graphql_points,
        "new_metadata_request_count": 0,
        "new_scan_attempts": 0,
        "changed_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_post_refresh_privacy_control(
    *, state: StateDB, repo_root: Path, run_id: str,
    reference_state_path: Path,
) -> dict[str, Any]:
    """Certify the one extra missing repository from the recovered epoch."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "post-refresh privacy control requires the failed reconcile run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        privacy = _validate_phase8_privacy_resume_control(
            contract["privacy_resume_control"],
            contract["graphql_resume_control"],
        )
        fresh_candidate = _validate_phase8_fresh_candidate_deferral_control(
            contract["fresh_candidate_deferral_control"], privacy
        )
        budget_control = _validate_phase8_visibility_budget_resume_control(
            contract["visibility_budget_resume_control"],
            contract["visibility_refresh_resume_control"],
        )
        transport = _validate_phase8_visibility_transport_retry_control(
            contract["visibility_transport_retry_control"], budget_control
        )
        epoch_recovery = _validate_phase8_visibility_epoch_recovery_control(
            contract["visibility_epoch_recovery_control"], transport
        )
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "post-refresh privacy run contract is malformed"
        ) from exc
    if (
        contract.get("post_refresh_privacy_control") is not None
        or epoch_recovery["current_network_task_source_sha256"]
        != contract.get("network_task_source_sha256")
        or contract.get("metadata_batch_size") != 100
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError(
            "post-refresh privacy run identity changed"
        )
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "post-refresh privacy found a changed safety budget"
        )
    reference_path = reference_state_path.resolve()
    if reference_path == state.path.resolve() or not reference_path.is_file():
        raise PipelineError(
            "post-refresh privacy reference is absent or live"
        )
    uri = "file:%s?mode=ro&immutable=1" % reference_path.as_posix()
    reference = sqlite3.connect(uri, uri=True)
    reference.row_factory = sqlite3.Row
    remaining_keys = list(privacy["remaining_deferred_task_keys"])
    scan_sql = """
        SELECT * FROM tasks WHERE run_id=? AND stage='scan'
        ORDER BY task_key
    """
    try:
        if reference.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise PipelineError(
                "post-refresh privacy reference failed quick_check"
            )
        reference_contract = json.loads(reference.execute(
            "SELECT plan_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()["plan_json"])["execution_contract"]
        if (
            reference_contract["privacy_resume_control"]["contract_sha256"]
            != privacy["contract_sha256"]
            or reference_contract["fresh_candidate_deferral_control"][
                "contract_sha256"
            ] != fresh_candidate["contract_sha256"]
            or reference_contract.get("post_refresh_privacy_control")
            is not None
        ):
            raise PipelineError(
                "post-refresh privacy reference contract changed"
            )
        reference_rows = list(reference.execute(scan_sql, (run_id,)))
        live_rows = list(state.connection.execute(scan_sql, (run_id,)))
        reference_by_key = {
            str(row["task_key"]): row for row in reference_rows
        }
        live_by_key = {str(row["task_key"]): row for row in live_rows}
        missing_keys = sorted(set(reference_by_key) - set(live_by_key))
        if (
            set(live_by_key) - set(reference_by_key)
            or len(reference_rows) != privacy["current_scan_task_count"]
            or len(live_rows) != 38286
            or len(missing_keys) != 1
        ):
            raise PipelineError(
                "post-refresh privacy scan universe changed"
            )
        missing = reference_by_key[missing_keys[0]]
        columns = [
            row[1] for row in reference.execute("PRAGMA table_info(tasks)")
        ]
        semantic_columns = [
            column for column in columns
            if column not in {"updated_at", "finished_at"}
        ]
        timestamp_refresh_proof = []
        for key, live in live_by_key.items():
            prior = reference_by_key[key]
            if any(
                live[column] != prior[column]
                for column in semantic_columns
            ):
                raise PipelineError(
                    "post-refresh privacy surviving scan task changed"
                )
            timestamps_changed = any(
                live[column] != prior[column]
                for column in ("updated_at", "finished_at")
            )
            if timestamps_changed:
                if (
                    key not in remaining_keys
                    or live["status"] != "failed"
                    or live["updated_at"] != live["finished_at"]
                ):
                    raise PipelineError(
                        "post-refresh privacy timestamp refresh changed"
                    )
                timestamp_refresh_proof.append({
                    "task_id": int(live["task_id"]),
                    "task_key": key,
                    "prior_updated_at": prior["updated_at"],
                    "prior_finished_at": prior["finished_at"],
                    "current_updated_at": live["updated_at"],
                    "current_finished_at": live["finished_at"],
                })
        timestamp_refresh_proof.sort(key=lambda item: item["task_key"])
        if (
            [item["task_key"] for item in timestamp_refresh_proof]
            != remaining_keys
        ):
            raise PipelineError(
                "post-refresh privacy deferred timestamp set changed"
            )
        try:
            missing_payload = json.loads(missing["payload_json"] or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "post-refresh privacy missing scan payload changed"
            ) from exc
        missing_node = str(missing["repository_id"])
        if (
            missing["status"] != "complete"
            or missing["attempts"] != 1
            or missing["error_code"] is not None
            or set(missing_payload) != {"full_name", "head_sha", "libraries"}
            or missing_payload["libraries"] != ["dali"]
        ):
            raise PipelineError(
                "post-refresh privacy missing scan evidence changed"
            )
        evidence_tables = {
            "repositories": ("node_id",),
            "candidates": ("repository_id",),
            "scan_results": ("repository_id",),
            "repo_analysis": ("repository_id",),
        }
        evidence_counts = {}
        evidence_proofs = {}
        for table, (column,) in evidence_tables.items():
            reference_count = int(reference.execute(
                "SELECT COUNT(*) FROM %s WHERE %s=?" % (table, column),
                (missing_node,),
            ).fetchone()[0])
            live_count = int(state.connection.execute(
                "SELECT COUNT(*) FROM %s WHERE %s=?" % (table, column),
                (missing_node,),
            ).fetchone()[0])
            if live_count != 0:
                raise PipelineError(
                    "post-refresh privacy purged evidence remains"
                )
            evidence_counts[table] = reference_count
            evidence_proofs[table] = _connection_query_proof(
                reference,
                "SELECT * FROM %s WHERE %s=? ORDER BY rowid" % (
                    table, column
                ),
                (missing_node,),
            )
        if evidence_counts != {
            "repositories": 1,
            "candidates": 3,
            "scan_results": 3,
            "repo_analysis": 2,
        }:
            raise PipelineError(
                "post-refresh privacy purged evidence partition changed"
            )
        missing_task_proof = _connection_query_proof(
            reference,
            "SELECT * FROM tasks WHERE task_id=?",
            (missing["task_id"],),
        )
        effective_detectors = {}
        for library_id, values in fingerprints["libraries"].items():
            filter_values = {
                "shared": fingerprints["filters"]["shared"]
            }
            if library_id == "nvpl":
                filter_values["nvpl"] = fingerprints["filters"]["nvpl"]
            effective_detectors[library_id] = fingerprint(
                "library:%s:effective-detector" % library_id,
                {
                    "detector": values["detector"],
                    "filters": filter_values,
                },
            )
        reference_repositories = list(reference.execute(
            """
            SELECT node_id,full_name,head_sha FROM repositories
            ORDER BY node_id
            """
        ))
        reference_by_identity = {}
        for repository in reference_repositories:
            identity_sha256 = hashlib.sha256(
                (
                    str(repository["node_id"]) + "\0"
                    + str(repository["full_name"])
                ).encode("utf-8")
            ).hexdigest()
            if identity_sha256 in reference_by_identity:
                raise PipelineError(
                    "post-refresh privacy reference identity changed"
                )
            reference_by_identity[identity_sha256] = repository
        deferred_head_pins = []
        for proof in fresh_candidate["deferred_task_proof"]:
            identity_sha256 = proof["repository_identity_sha256"]
            repository = reference_by_identity.get(identity_sha256)
            libraries = sorted(proof["libraries"])
            if repository is None or not re.fullmatch(
                r"[0-9a-f]{40}", str(repository["head_sha"])
            ):
                raise PipelineError(
                    "post-refresh privacy deferred reference changed"
                )
            task_key = fingerprint(
                "scan-task-v2",
                {
                    "repository_node_id": str(repository["node_id"]),
                    "head_sha": str(repository["head_sha"]),
                    "candidate_library_ids": libraries,
                    "analysis_only": False,
                    "ai_fingerprint": None,
                    "detector_fingerprints": {
                        library_id: effective_detectors[library_id]
                        for library_id in libraries
                    },
                },
            )
            if task_key != proof["task_key"]:
                raise PipelineError(
                    "post-refresh privacy deferred reference changed"
                )
            deferred_head_pins.append({
                "task_key": task_key,
                "repository_identity_sha256": identity_sha256,
                "head_sha": str(repository["head_sha"]),
                "libraries": libraries,
            })
        deferred_head_pins.sort(key=lambda item: item["task_key"])
        if len(deferred_head_pins) != 8:
            raise PipelineError(
                "post-refresh privacy deferred reference changed"
            )
    finally:
        reference.close()

    fresh_epoch = epoch_recovery["resume_metadata_epoch"]
    fresh_rows = list(state.connection.execute(
        """
        SELECT task_id,task_key,status,result_json FROM tasks
        WHERE run_id=? AND stage='github-metadata-batch'
          AND task_key LIKE ? ORDER BY task_id
        """,
        (run_id, "fresh:" + fresh_epoch + ":%"),
    ))
    if len(fresh_rows) != 388 or any(
        row["status"] != "complete" for row in fresh_rows
    ):
        raise PipelineError(
            "post-refresh privacy recovered metadata epoch changed"
        )
    missing_documents = []
    for row in fresh_rows:
        try:
            document = json.loads(row["result_json"] or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "post-refresh privacy metadata evidence is malformed"
            ) from exc
        for repository in document.get("repositories", []):
            if repository.get("requested_node_id") == missing_node:
                missing_documents.append({
                    "task_id": int(row["task_id"]),
                    "task_key_sha256": hashlib.sha256(
                        str(row["task_key"]).encode("utf-8")
                    ).hexdigest(),
                    "repository": repository,
                })
    if len(missing_documents) != 1:
        raise PipelineError(
            "post-refresh privacy missing metadata proof changed"
        )
    missing_repository = missing_documents[0]["repository"]
    if (
        missing_repository.get("status") != "missing"
        or missing_repository.get("admitted_public") is not False
        or missing_repository.get("requested_node_id") != missing_node
        or missing_repository.get("requested_full_name")
        != missing_payload["full_name"]
        or missing_repository.get("error_count") != 0
    ):
        raise PipelineError(
            "post-refresh privacy metadata status changed"
        )
    placeholders = ",".join("?" for _ in remaining_keys)
    deferred_rows = list(state.connection.execute(
        f"""
        SELECT task_key,status,repository_id,payload_json FROM tasks
        WHERE run_id=? AND stage='scan' AND task_key IN ({placeholders})
        ORDER BY task_key
        """,
        (run_id, *remaining_keys),
    ))
    if (
        len(deferred_rows) != len(remaining_keys)
        or [str(row["task_key"]) for row in deferred_rows] != remaining_keys
        or any(row["status"] != "failed" for row in deferred_rows)
    ):
        raise PipelineError(
            "post-refresh privacy deferred partition changed"
        )
    deferred_proof = []
    for row in deferred_rows:
        payload = json.loads(row["payload_json"] or "{}")
        deferred_proof.append({
            "task_key": str(row["task_key"]),
            "repository_id": str(row["repository_id"]),
            "full_name": payload["full_name"],
            "head_sha": payload["head_sha"],
            "libraries": sorted(payload["libraries"]),
        })
    if _canonical_sha256(deferred_proof) != privacy[
        "remaining_deferred_repository_proof_sha256"
    ]:
        raise PipelineError(
            "post-refresh privacy deferred proof changed"
        )
    counts = dict(state.connection.execute(
        """
        SELECT status,COUNT(*) FROM tasks WHERE run_id=? AND stage='scan'
        GROUP BY status
        """,
        (run_id,),
    ).fetchall())
    if counts != {"complete": 37968, "failed": 318}:
        raise PipelineError(
            "post-refresh privacy current scan partition changed"
        )
    head_pins = int(state.connection.execute(
        """
        SELECT COUNT(*) FROM tasks t JOIN repositories r
          ON r.node_id=t.repository_id
        WHERE t.run_id=? AND t.stage='scan'
          AND json_extract(t.payload_json,'$.head_sha')<>r.head_sha
        """,
        (run_id,),
    ).fetchone()[0])
    renames = int(state.connection.execute(
        """
        SELECT COUNT(*) FROM tasks t JOIN repositories r
          ON r.node_id=t.repository_id
        WHERE t.run_id=? AND t.stage='scan'
          AND lower(json_extract(t.payload_json,'$.full_name'))
              <>lower(r.full_name)
        """,
        (run_id,),
    ).fetchone()[0])
    if head_pins != 1538 or renames != 16:
        raise PipelineError(
            "post-refresh privacy scan-bound metadata delta changed"
        )
    remaining_scan_proof = _connection_query_proof(
        state.connection,
        """
        SELECT task_id,run_id,stage,task_key,repository_id,library_id,
               payload_json,result_json,status,attempts,max_attempts,
               lease_owner,lease_expires_at,available_at,error_code,created_at
        FROM tasks WHERE run_id=? AND stage='scan' ORDER BY task_key
        """,
        (run_id,),
    )
    evidence_proof = {
        "task": missing_task_proof,
        "tables": evidence_proofs,
    }
    audit = _post_refresh_privacy_source_audit(
        repo_root, epoch_recovery["current_network_task_source_sha256"]
    )
    with state.transaction(immediate=True):
        before = _downstream_preserved_state(
            state, run_id,
            control_stage=_POST_REFRESH_PRIVACY_CONTROL_STAGE,
        )
        control = {
            "version": 2,
            "kind": "phase8-post-refresh-privacy-control",
            "policy": (
                "adopt-one-additional-nonpublic-purge-and-pin-surviving-evidence"
            ),
            "predecessor_source_commit": audit["predecessor_source_commit"],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "privacy_resume_contract_sha256": privacy["contract_sha256"],
            "visibility_epoch_recovery_contract_sha256": epoch_recovery[
                "contract_sha256"
            ],
            "reference_state_name": reference_path.name,
            "fresh_metadata_epoch": fresh_epoch,
            "fresh_metadata_batch_count": len(fresh_rows),
            "prior_scan_task_count": privacy["current_scan_task_count"],
            "current_scan_task_count": sum(counts.values()),
            "prior_completed_scan_task_count": privacy[
                "current_completed_scan_task_count"
            ],
            "current_completed_scan_task_count": counts["complete"],
            "current_deferred_scan_task_count": counts["failed"],
            "additional_purged_scan_task_count": 1,
            "additional_purged_completed_scan_task_count": 1,
            "additional_purged_deferred_scan_task_count": 0,
            "additional_purged_repository_count": evidence_counts[
                "repositories"
            ],
            "additional_purged_candidate_count": evidence_counts[
                "candidates"
            ],
            "additional_purged_scan_result_count": evidence_counts[
                "scan_results"
            ],
            "additional_purged_repo_analysis_count": evidence_counts[
                "repo_analysis"
            ],
            "additional_purged_task_keys_sha256": _canonical_sha256(
                missing_keys
            ),
            "additional_purged_repository_nodes_sha256": _canonical_sha256(
                [missing_node]
            ),
            "additional_purged_evidence_sha256": _canonical_sha256(
                evidence_proof
            ),
            "fresh_missing_metadata_proof_sha256": _canonical_sha256(
                missing_documents
            ),
            "remaining_deferred_task_keys": remaining_keys,
            "remaining_deferred_task_keys_sha256": _canonical_sha256(
                remaining_keys
            ),
            "remaining_deferred_repository_proof_sha256": _canonical_sha256(
                deferred_proof
            ),
            "deferred_scan_head_pin_count": len(deferred_head_pins),
            "deferred_scan_head_pins": deferred_head_pins,
            "deferred_scan_head_pins_sha256": _canonical_sha256(
                deferred_head_pins
            ),
            "scan_head_pin_count": head_pins,
            "scan_bound_rename_count": renames,
            "deferred_timestamp_refresh_count": len(
                timestamp_refresh_proof
            ),
            "deferred_timestamp_refresh_rows_sha256": _canonical_sha256(
                timestamp_refresh_proof
            ),
            "remaining_scan_task_rows_sha256": remaining_scan_proof[
                "rows_sha256"
            ],
            "preserved_state_sha256": before["snapshot_sha256"],
            "new_metadata_request_count": 0,
            "new_scan_attempts": 0,
            "changed_surviving_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["post_refresh_privacy_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract, mode="reconcile", wanted=selected,
            budgets=budgets, metadata_batch_size=100,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "post-refresh privacy reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "post-refresh privacy run changed concurrently"
            )
        state.update_stage(
            run_id, _POST_REFRESH_PRIVACY_CONTROL_STAGE,
            status="complete",
            counters={
                "additional_purged_scan_tasks": 1,
                "remaining_scan_tasks": sum(counts.values()),
                "remaining_deferred_scan_tasks": counts["failed"],
                "scan_heads_to_pin": head_pins,
            },
            metrics={
                "additional_purged_candidates": evidence_counts[
                    "candidates"
                ],
                "additional_purged_scan_results": evidence_counts[
                    "scan_results"
                ],
                "additional_purged_repo_analysis": evidence_counts[
                    "repo_analysis"
                ],
                "deferred_timestamp_refreshes": len(
                    timestamp_refresh_proof
                ),
                "new_metadata_request_count": 0,
                "new_scan_attempts": 0,
                "changed_surviving_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control, "preserved_state": before},
        )
        after = _downstream_preserved_state(
            state, run_id,
            control_stage=_POST_REFRESH_PRIVACY_CONTROL_STAGE,
        )
        if after != before:
            raise PipelineError(
                "post-refresh privacy control changed preserved state"
            )
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "additional_purged_scan_tasks": 1,
        "additional_purged_scan_results": 3,
        "additional_purged_repo_analysis": 2,
        "additional_purged_candidates": 3,
        "remaining_scan_tasks": 38286,
        "remaining_completed_scan_tasks": 37968,
        "remaining_deferred_scan_tasks": 318,
        "deferred_timestamp_refreshes": 318,
        "new_metadata_request_count": 0,
        "new_scan_attempts": 0,
        "changed_surviving_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_final_visibility_privacy_control(
    *, state: StateDB, repo_root: Path, run_id: str,
) -> dict[str, Any]:
    """Quarantine the exact newly missing final-visibility repository."""
    run = state.connection.execute(
        "SELECT * FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "final-visibility privacy control requires the failed reconcile "
            "run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        privacy = _validate_phase8_privacy_resume_control(
            contract["privacy_resume_control"],
            contract["graphql_resume_control"],
        )
        post_refresh = _validate_phase8_post_refresh_privacy_control(
            contract["post_refresh_privacy_control"], privacy,
            contract["visibility_epoch_recovery_control"],
        )
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        selected = set(contract["selected_library_ids"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "final-visibility privacy run contract is malformed"
        ) from exc
    if (
        contract.get("final_visibility_privacy_control") is not None
        or post_refresh["current_network_task_source_sha256"]
        != contract.get("network_task_source_sha256")
        or contract.get("metadata_batch_size") != 100
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError(
            "final-visibility privacy run identity changed"
        )
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "final-visibility privacy found a changed safety budget"
        )
    stages = dict(state.connection.execute(
        "SELECT stage,status FROM stages WHERE run_id=?", (run_id,)
    ).fetchall())
    if (
        stages.get("scan") != "complete"
        or stages.get("aggregation") != "complete"
        or stages.get("citations") != "complete"
        or stages.get("final_visibility") != "failed"
        or stages.get("publication") != "failed"
    ):
        raise PipelineError(
            "final-visibility privacy stage boundary changed"
        )

    all_final_rows = list(state.connection.execute(
        """
        SELECT task_id,task_key,status,payload_json,result_json
        FROM tasks WHERE run_id=?
          AND stage='github-final-visibility-batch' ORDER BY task_id
        """,
        (run_id,),
    ))
    epochs: dict[str, list[sqlite3.Row]] = {}
    payloads: dict[int, dict[str, Any]] = {}
    for row in all_final_rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
            epoch = payload["epoch"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "final-visibility privacy task payload is malformed"
            ) from exc
        if not isinstance(epoch, str):
            raise PipelineError(
                "final-visibility privacy task epoch changed"
            )
        payloads[int(row["task_id"])] = payload
        epochs.setdefault(epoch, []).append(row)
    if not epochs:
        raise PipelineError(
            "final-visibility privacy task epoch is absent"
        )
    final_epoch, final_rows = list(epochs.items())[-1]
    statuses = {}
    for row in final_rows:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    if len(final_rows) != 291 or statuses != {
        "complete": 172, "pending": 119,
    }:
        raise PipelineError(
            "final-visibility privacy task partition changed"
        )
    set_sha256s = {
        payloads[int(row["task_id"])].get("set_sha256")
        for row in final_rows
    }
    checked_ats = {
        payloads[int(row["task_id"])].get("checked_at")
        for row in final_rows
    }
    if (
        len(set_sha256s) != 1
        or len(checked_ats) != 1
        or any(
            payloads[int(row["task_id"])].get("epoch") != final_epoch
            or payloads[int(row["task_id"])].get("version") != 1
            or not isinstance(
                payloads[int(row["task_id"])].get("lookups"), list
            )
            for row in final_rows
        )
    ):
        raise PipelineError(
            "final-visibility privacy epoch identity changed"
        )

    rejected: list[tuple[sqlite3.Row, dict[str, Any], dict[str, Any]]] = []
    for row in final_rows:
        if row["status"] != "complete":
            if row["result_json"] is not None:
                raise PipelineError(
                    "final-visibility pending task retained a result"
                )
            continue
        try:
            result = json.loads(row["result_json"] or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "final-visibility privacy result is malformed"
            ) from exc
        lookups = payloads[int(row["task_id"])]["lookups"]
        expected = [lookup.get("node_id") for lookup in lookups]
        repositories = result.get("repositories")
        if (
            not isinstance(repositories, list)
            or len(repositories) != len(expected)
            or {item.get("request_key") for item in repositories}
            != {"node:" + node_id for node_id in expected}
            or result.get("errors")
        ):
            raise PipelineError(
                "final-visibility privacy completed task coverage changed"
            )
        for repository in repositories:
            requested_node = repository.get("requested_node_id")
            if repository.get("status") == "ok":
                if (
                    requested_node not in expected
                    or repository.get("requested_full_name") is not None
                    or repository.get("node_id") != requested_node
                    or repository.get("is_fork") is not False
                    or repository.get("is_archived") is not False
                    or repository.get("admitted_public") is not True
                    or repository.get("error_count") != 0
                ):
                    raise PipelineError(
                        "final-visibility public result changed"
                    )
                continue
            rejected.append((row, payloads[int(row["task_id"])], repository))
    if len(rejected) != 1:
        raise PipelineError(
            "final-visibility privacy rejection set changed"
        )
    rejected_row, rejected_payload, rejected_repository = rejected[0]
    rejected_node = rejected_repository.get("requested_node_id")
    if (
        int(rejected_row["task_id"]) != 414688
        or not isinstance(rejected_node, str)
        or not rejected_node
        or rejected_repository.get("requested_full_name") is not None
        or rejected_repository.get("node_id") is not None
        or rejected_repository.get("full_name") is not None
        or rejected_repository.get("status") != "missing"
        or rejected_repository.get("admitted_public") is not False
        or rejected_repository.get("error_count") != 0
    ):
        raise PipelineError(
            "final-visibility privacy missing-node proof changed"
        )

    repository = state.connection.execute(
        "SELECT node_id,full_name FROM repositories WHERE node_id=?",
        (rejected_node,),
    ).fetchone()
    if repository is None:
        raise PipelineError(
            "final-visibility privacy repository is already absent"
        )
    identity_sha256 = hashlib.sha256(
        (
            str(repository["node_id"]) + "\0"
            + str(repository["full_name"])
        ).encode("utf-8")
    ).hexdigest()
    evidence_queries = {
        "repositories": (
            "SELECT * FROM repositories WHERE node_id=? ORDER BY rowid",
            (rejected_node,),
        ),
        "candidates": (
            "SELECT * FROM candidates WHERE repository_id=? ORDER BY rowid",
            (rejected_node,),
        ),
        "scan_results": (
            "SELECT * FROM scan_results WHERE repository_id=? ORDER BY rowid",
            (rejected_node,),
        ),
        "repo_analysis": (
            "SELECT * FROM repo_analysis WHERE repository_id=? ORDER BY rowid",
            (rejected_node,),
        ),
        "scan_tasks": (
            """
            SELECT * FROM tasks WHERE run_id=? AND stage='scan'
              AND repository_id=? ORDER BY task_id
            """,
            (run_id, rejected_node),
        ),
    }
    evidence_proofs = {
        name: _connection_query_proof(state.connection, sql, params)
        for name, (sql, params) in evidence_queries.items()
    }
    evidence_counts = {
        name: proof["row_count"] for name, proof in evidence_proofs.items()
    }
    if evidence_counts != {
        "repositories": 1, "candidates": 8, "scan_results": 2,
        "repo_analysis": 2, "scan_tasks": 1,
    }:
        raise PipelineError(
            "final-visibility privacy evidence partition changed"
        )
    scan_task = state.connection.execute(
        """
        SELECT task_id,task_key,status,attempts,error_code,payload_json
        FROM tasks WHERE run_id=? AND stage='scan' AND repository_id=?
        """,
        (run_id, rejected_node),
    ).fetchone()
    if (
        scan_task["status"] != "complete"
        or scan_task["attempts"] != 1
        or scan_task["error_code"] is not None
    ):
        raise PipelineError(
            "final-visibility privacy scan task changed"
        )
    scan_attempt_proof = _connection_query_proof(
        state.connection,
        "SELECT * FROM scan_attempts WHERE task_id=? ORDER BY attempt",
        (scan_task["task_id"],),
    )
    if scan_attempt_proof["row_count"] != 1:
        raise PipelineError(
            "final-visibility privacy scan attempt changed"
        )

    remaining_keys = list(post_refresh["remaining_deferred_task_keys"])
    placeholders = ",".join("?" for _ in remaining_keys)
    deferred_rows = list(state.connection.execute(
        f"""
        SELECT task_key,status,repository_id,payload_json FROM tasks
        WHERE run_id=? AND stage='scan' AND task_key IN ({placeholders})
        ORDER BY task_key
        """,
        (run_id, *remaining_keys),
    ))
    deferred_proof = []
    for row in deferred_rows:
        payload = json.loads(row["payload_json"] or "{}")
        deferred_proof.append({
            "task_key": str(row["task_key"]),
            "repository_id": str(row["repository_id"]),
            "full_name": payload["full_name"],
            "head_sha": payload["head_sha"],
            "libraries": sorted(payload["libraries"]),
        })
    if (
        len(deferred_rows) != 318
        or any(row["status"] != "failed" for row in deferred_rows)
        or _canonical_sha256(deferred_proof)
        != post_refresh["remaining_deferred_repository_proof_sha256"]
    ):
        raise PipelineError(
            "final-visibility privacy deferred partition changed"
        )
    scan_counts = dict(state.connection.execute(
        """
        SELECT status,COUNT(*) FROM tasks WHERE run_id=? AND stage='scan'
        GROUP BY status
        """,
        (run_id,),
    ).fetchall())
    if scan_counts != {"complete": 37968, "failed": 318}:
        raise PipelineError(
            "final-visibility privacy scan partition changed"
        )
    # The failed coordinator already applied the certified head pins before
    # staging, so the live repository rows no longer expose the pre-pin delta.
    # The next resume rebuilds fresh metadata first and must reproduce the
    # already sealed post-refresh counts.  The rejected repository contributes
    # neither a head change nor a rename, as proved directly below.
    scan_payload = json.loads(scan_task["payload_json"] or "{}")
    current_repository = state.connection.execute(
        "SELECT full_name,head_sha FROM repositories WHERE node_id=?",
        (rejected_node,),
    ).fetchone()
    if (
        current_repository is None
        or scan_payload.get("head_sha") != current_repository["head_sha"]
        or str(scan_payload.get("full_name", "")).casefold()
        != str(current_repository["full_name"]).casefold()
    ):
        raise PipelineError(
            "final-visibility privacy rejected scan binding changed"
        )
    head_pins = int(post_refresh["scan_head_pin_count"])
    renames = int(post_refresh["scan_bound_rename_count"])
    if head_pins != 1538 or renames != 16:
        raise PipelineError(
            "final-visibility privacy scan-bound delta changed"
        )
    final_tasks_proof = _connection_query_proof(
        state.connection,
        """
        SELECT * FROM tasks WHERE run_id=?
          AND stage='github-final-visibility-batch' ORDER BY task_id
        """,
        (run_id,),
    )
    citation_cache_proof = _connection_query_proof(
        state.connection,
        "SELECT * FROM citation_cache ORDER BY library_id,query_fp,work_id",
    )
    rejection_proof = {
        "task_id": int(rejected_row["task_id"]),
        "task_key_sha256": hashlib.sha256(
            str(rejected_row["task_key"]).encode("utf-8")
        ).hexdigest(),
        "payload_sha256": _canonical_sha256(rejected_payload),
        "repository": rejected_repository,
    }
    evidence_proof = {
        "tables": evidence_proofs,
        "scan_attempts": scan_attempt_proof,
    }
    audit = _final_visibility_privacy_source_audit(
        repo_root, post_refresh["current_network_task_source_sha256"]
    )

    with state.transaction(immediate=True):
        deleted = state.connection.execute(
            "DELETE FROM repositories WHERE node_id=?", (rejected_node,)
        ).rowcount
        if deleted != 1:
            raise PipelineError(
                "final-visibility privacy repository purge changed"
            )
        for name, (sql, params) in evidence_queries.items():
            if name == "scan_tasks":
                remaining = state.connection.execute(
                    """
                    SELECT COUNT(*) FROM tasks WHERE run_id=? AND stage='scan'
                      AND repository_id=?
                    """,
                    params,
                ).fetchone()[0]
            else:
                remaining = state.connection.execute(
                    "SELECT COUNT(*) FROM " + name + " WHERE "
                    + ("node_id" if name == "repositories" else "repository_id")
                    + "=?",
                    params,
                ).fetchone()[0]
            if remaining:
                raise PipelineError(
                    "final-visibility privacy purged evidence remains"
                )
        counts_after = dict(state.connection.execute(
            """
            SELECT status,COUNT(*) FROM tasks
            WHERE run_id=? AND stage='scan' GROUP BY status
            """,
            (run_id,),
        ).fetchall())
        if counts_after != {"complete": 37967, "failed": 318}:
            raise PipelineError(
                "final-visibility privacy post-purge scan partition changed"
            )
        control = {
            "version": 1,
            "kind": "phase8-final-visibility-privacy-control",
            "policy": (
                "purge-one-final-missing-node-and-resume-compatible-epoch"
            ),
            "predecessor_source_commit": audit[
                "predecessor_source_commit"
            ],
            "successor_source_commit": audit["successor_source_commit"],
            "changed_paths": audit["changed_paths"],
            "source_audit_sha256": audit["source_audit_sha256"],
            "prior_network_task_source_sha256": audit[
                "prior_network_task_source_sha256"
            ],
            "current_network_task_source_sha256": audit[
                "current_network_task_source_sha256"
            ],
            "post_refresh_privacy_contract_sha256": post_refresh[
                "contract_sha256"
            ],
            "final_visibility_epoch": final_epoch,
            "final_visibility_task_count": len(final_rows),
            "final_visibility_completed_task_count": statuses["complete"],
            "final_visibility_pending_task_count": statuses["pending"],
            "rejected_task_id": int(rejected_row["task_id"]),
            "rejected_task_key_sha256": hashlib.sha256(
                str(rejected_row["task_key"]).encode("utf-8")
            ).hexdigest(),
            "rejected_repository_node_sha256": hashlib.sha256(
                rejected_node.encode("utf-8")
            ).hexdigest(),
            "rejected_repository_identity_sha256": identity_sha256,
            "rejected_final_visibility_proof_sha256": _canonical_sha256(
                rejection_proof
            ),
            "prior_scan_task_count": 38286,
            "current_scan_task_count": 38285,
            "prior_completed_scan_task_count": 37968,
            "current_completed_scan_task_count": 37967,
            "current_deferred_scan_task_count": 318,
            "purged_scan_task_count": 1,
            "purged_completed_scan_task_count": 1,
            "purged_deferred_scan_task_count": 0,
            "purged_repository_count": 1,
            "purged_candidate_count": 8,
            "purged_scan_result_count": 2,
            "purged_repo_analysis_count": 2,
            "purged_scan_attempt_count": 1,
            "purged_task_key_sha256": _canonical_sha256([
                str(scan_task["task_key"])
            ]),
            "purged_evidence_sha256": _canonical_sha256(evidence_proof),
            "remaining_deferred_task_keys": remaining_keys,
            "remaining_deferred_task_keys_sha256": _canonical_sha256(
                remaining_keys
            ),
            "remaining_deferred_repository_proof_sha256": post_refresh[
                "remaining_deferred_repository_proof_sha256"
            ],
            "deferred_scan_head_pin_count": post_refresh[
                "deferred_scan_head_pin_count"
            ],
            "deferred_scan_head_pins": post_refresh[
                "deferred_scan_head_pins"
            ],
            "deferred_scan_head_pins_sha256": post_refresh[
                "deferred_scan_head_pins_sha256"
            ],
            "scan_head_pin_count": head_pins,
            "scan_bound_rename_count": renames,
            "preserved_final_visibility_tasks_sha256": final_tasks_proof[
                "rows_sha256"
            ],
            "preserved_citation_cache_sha256": citation_cache_proof[
                "rows_sha256"
            ],
            "new_metadata_request_count": 0,
            "new_final_visibility_request_count": 0,
            "new_scan_attempts": 0,
            "changed_surviving_scan_results": 0,
            "changed_citation_cache_entries": 0,
            "other_budget_changes": 0,
        }
        control["contract_sha256"] = _canonical_sha256(control)
        updated_plan = copy.deepcopy(plan)
        updated_contract = dict(contract)
        updated_contract["network_task_source_sha256"] = audit[
            "current_network_task_source_sha256"
        ]
        updated_contract["final_visibility_privacy_control"] = control
        updated_plan["execution_contract"] = updated_contract
        reviewed = _validate_reviewed_execution_contract(
            updated_contract, mode="reconcile", wanted=selected,
            budgets=budgets, metadata_batch_size=100,
        )
        if reviewed != updated_contract:
            raise PipelineError(
                "final-visibility privacy reviewed contract changed"
            )
        changed = state.connection.execute(
            "UPDATE runs SET plan_json=? WHERE run_id=? AND plan_json=?",
            (canonical_json(updated_plan), run_id, run["plan_json"]),
        ).rowcount
        if changed != 1:
            raise PipelineError(
                "final-visibility privacy run changed concurrently"
            )
        state.update_stage(
            run_id, _FINAL_VISIBILITY_PRIVACY_CONTROL_STAGE,
            status="complete",
            counters={
                "purged_scan_tasks": 1,
                "remaining_scan_tasks": 38285,
                "remaining_deferred_scan_tasks": 318,
                "preserved_final_visibility_completed_tasks": 172,
                "remaining_final_visibility_pending_tasks": 119,
            },
            metrics={
                "purged_candidates": 8,
                "purged_scan_results": 2,
                "purged_repo_analysis": 2,
                "new_metadata_request_count": 0,
                "new_final_visibility_request_count": 0,
                "new_scan_attempts": 0,
                "changed_surviving_scan_results": 0,
                "changed_citation_cache_entries": 0,
                "other_budget_changes": 0,
            },
            checkpoint={"control": control},
        )
        if _connection_query_proof(
            state.connection,
            """
            SELECT * FROM tasks WHERE run_id=?
              AND stage='github-final-visibility-batch' ORDER BY task_id
            """,
            (run_id,),
        ) != final_tasks_proof:
            raise PipelineError(
                "final-visibility privacy changed attestation tasks"
            )
        if _connection_query_proof(
            state.connection,
            "SELECT * FROM citation_cache ORDER BY library_id,query_fp,work_id",
        ) != citation_cache_proof:
            raise PipelineError(
                "final-visibility privacy changed citation cache"
            )
    return {
        "run_id": run_id,
        "status": "failed",
        "control": control,
        "purged_scan_tasks": 1,
        "purged_candidates": 8,
        "purged_scan_results": 2,
        "purged_repo_analysis": 2,
        "remaining_scan_tasks": 38285,
        "remaining_completed_scan_tasks": 37967,
        "remaining_deferred_scan_tasks": 318,
        "preserved_final_visibility_completed_tasks": 172,
        "remaining_final_visibility_pending_tasks": 119,
        "new_metadata_request_count": 0,
        "new_final_visibility_request_count": 0,
        "new_scan_attempts": 0,
        "changed_surviving_scan_results": 0,
        "changed_citation_cache_entries": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }
