"""One-time audited Phase 8 scanner-source compatibility migration.

The production run may adopt only the already-audited issue-lane commits.  The
control proves their exact source ancestry, proves that the only fingerprint
changes are the shared generated-output filter and shared scanner source, and
then re-keys immutable clean results without replaying compatible scans.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping

from .fingerprints import canonical_json, fingerprint
from .phase8_control import (
    _compiled_regex_declaration,
    _enforce_scan_attempt_budgets,
    _scan_attempt_usage_for_run,
    _sha256,
)
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
    _validate_certified_scan_checkpoint_contract,
)


_PREDECESSOR_COMMIT = "aafdc5e14d6b814b5e53e59f266c485bdffc586b"
_AUDITED_ISSUE_COMMITS = (
    "e4ce70f21d09d937bb02052dc6e45a07aea4a165",
    "034ebee476211a3bbb9c0ec8259a482d878bdfac",
    "b1e69e56ef030623848dbac351d06d0bd833209f",
)
_AUDITED_ISSUE_COMMIT = _AUDITED_ISSUE_COMMITS[-1]
_ISSUE_PATHS = frozenset({
    "collector/config.py",
    "collector/repo_cache.py",
    "collector/scan.py",
    "test_req14_content_materialization.py",
    "test_req14_scanner.py",
})
_CONTROL_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_source_migration.py",
    "collector/pipeline.py",
    "ops/req14_detector_fingerprints.json",
    "test_req14_pipeline.py",
})
_VIRTUAL_DOCUMENTS_SEGMENT_RE = re.compile(
    r"(?:\A|/)\.virtual_documents/", re.IGNORECASE
)
_TASK_UNIVERSE = 38321
_SOURCE_RETRY_MARKER = "issue_retry:audited_scanner_source_migration"
_SOURCE_RETRY_CONTROL_PATHS = frozenset({
    "collector/cli.py",
    "collector/phase8_source_migration.py",
    "collector/state.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "test_req14_scan_attempts.py",
    "test_req14_successor.py",
})
_SOURCE_RETRY_INCIDENTS = (
    {
        "full_name": "HackersCardgame/hacker-notes-s24m03",
        "head_sha": "97ebedb5242edbd55b54431f64f3e417143a9a87",
        "libraries": ("ovrtx",),
        "task_error_code": "repository_cache_integrity",
        "attempt_error_code": "repository_cache_integrity",
        "error_detail": "current-tree object is unavailable after hydration",
        "attempts": 2,
        "max_attempts": 2,
        "retryable": True,
        "remediation": "raw-nul-delimited-tree-path-pruning",
    },
    {
        "full_name": "albumentations-team/benchmark",
        "head_sha": "6d9924748acaa8eaf789fc16b9a60a2c4d5079cb",
        "libraries": ("dali",),
        "task_error_code": "detector_error",
        "attempt_error_code": "detector_error",
        "error_detail": (
            "detector scan failed: scan attempt 1/1 failed: "
            "albumentations-team/benchmark (dependency/build evidence is "
            "not a regular file: requirements/dali-video.in) | skipping "
            "after 1 failed attempts: albumentations-team/benchmark"
        ),
        "attempts": 1,
        "max_attempts": 2,
        "retryable": False,
        "remediation": "authored-in-repository-manifest-symlink",
    },
    {
        "full_name": "lchyeon0123/Kairos",
        "head_sha": "562ba7b680761e420e60eb7aa86976bd03cd119e",
        "libraries": ("cufft",),
        "task_error_code": "repository_cache_integrity",
        "attempt_error_code": "repository_cache_integrity",
        "error_detail": (
            "detector-relevant sparse path is unavailable: CMakeLists.txt"
        ),
        "attempts": 2,
        "max_attempts": 2,
        "retryable": True,
        "remediation": "pinned-non-regular-lfs-index-mode",
    },
    {
        "full_name": "qompassai/PathFinders",
        "head_sha": "5af9837e6538881a2a257cfb938e5026f4860a1b",
        "libraries": ("dali",),
        "task_error_code": "invalid_notebook",
        "attempt_error_code": "invalid_notebook",
        "error_detail": (
            "tracked notebook is invalid JSON; scan is incomplete: "
            "Youth/SpaceInvaders/.virtual_documents/spaceinvaders.ipynb"
        ),
        "attempts": 1,
        "max_attempts": 2,
        "retryable": False,
        "remediation": "exact-virtual-documents-generated-output",
    },
)
_STALE_COORDINATOR_INCIDENT = {
    "full_name": "DeNA/DeClang",
    "head_sha": "62389ff192c43e418ece322a4bcd7fc186d17f99",
    "libraries": ("cusparse", "cusparselt", "cutensor"),
    "attempts": 2,
    "max_attempts": 2,
}


def _document_virtual_paths(value: Any) -> list[str]:
    matches: list[str] = []
    if isinstance(value, Mapping):
        for nested in value.values():
            matches.extend(_document_virtual_paths(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            matches.extend(_document_virtual_paths(nested))
    elif isinstance(value, str) and _VIRTUAL_DOCUMENTS_SEGMENT_RE.search(value):
        matches.append(value)
    return matches


def _effective_detectors(document: Mapping[str, Any]) -> dict[str, str]:
    libraries = document.get("libraries") or {}
    filters = document.get("filters") or {}
    shared = filters.get("shared")
    if not isinstance(libraries, Mapping) or not isinstance(shared, str):
        raise PipelineError("scanner migration fingerprints are malformed")
    values = {}
    for library_id, library_fingerprints in libraries.items():
        if not isinstance(library_fingerprints, Mapping):
            raise PipelineError("scanner migration fingerprints are malformed")
        detector = library_fingerprints.get("detector")
        if not isinstance(detector, str):
            raise PipelineError("scanner migration detector is malformed")
        filter_values = {"shared": shared}
        if library_id == "nvpl":
            nvpl = filters.get("nvpl")
            if not isinstance(nvpl, str):
                raise PipelineError("scanner migration NVPL filter is malformed")
            filter_values["nvpl"] = nvpl
        values[str(library_id)] = fingerprint(
            "library:%s:effective-detector" % library_id,
            {"detector": detector, "filters": filter_values},
        )
    return values


def _source_audit(repo_root: Path, prior_network_sha256: str) -> dict[str, Any]:
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError("scanner migration requires a clean tracked worktree")
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    predecessor = str(
        _git(repo_root, "rev-parse", _PREDECESSOR_COMMIT + "^{commit}")
    ).strip()
    audited = str(
        _git(repo_root, "rev-parse", _AUDITED_ISSUE_COMMIT + "^{commit}")
    ).strip()
    if predecessor != _PREDECESSOR_COMMIT or audited != _AUDITED_ISSUE_COMMIT:
        raise PipelineError("scanner migration source identity changed")
    for before, after in ((predecessor, audited), (audited, head)):
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", before, after],
            cwd=repo_root,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if ancestor.returncode:
            raise PipelineError("scanner migration source ancestry changed")
    commits = tuple(
        line
        for line in str(
            _git(
                repo_root,
                "rev-list",
                "--reverse",
                predecessor + ".." + audited,
            )
        ).splitlines()
        if line
    )
    if commits != _AUDITED_ISSUE_COMMITS:
        raise PipelineError("scanner migration audited commit chain changed")

    def changed_paths(before: str, after: str) -> tuple[str, ...]:
        return tuple(sorted(
            line
            for line in str(
                _git(repo_root, "diff", "--name-only", before + ".." + after)
            ).splitlines()
            if line
        ))

    issue_paths = changed_paths(predecessor, audited)
    control_paths = changed_paths(audited, head)
    if set(issue_paths) != _ISSUE_PATHS:
        raise PipelineError("scanner migration issue-lane path set changed")
    if (
        not {"collector/phase8_source_migration.py", "collector/pipeline.py"}
        <= set(control_paths)
        or set(control_paths) - _CONTROL_PATHS
    ):
        raise PipelineError("scanner migration control path set changed")

    predecessor_config = bytes(
        _git(repo_root, "show", predecessor + ":collector/config.py", text=False)
    )
    audited_config = bytes(
        _git(repo_root, "show", audited + ":collector/config.py", text=False)
    )
    current_config = (repo_root / "collector/config.py").read_bytes()
    before = _compiled_regex_declaration(
        predecessor_config, "ENV_DUMP_PATH_RE"
    )
    after = _compiled_regex_declaration(audited_config, "ENV_DUMP_PATH_RE")
    expected_pattern = before["pattern"].replace(
        r"\.ipynb_checkpoints",
        r"\.ipynb_checkpoints|\.virtual_documents",
        1,
    )
    if (
        audited_config != current_config
        or before["pattern"].count(r"\.ipynb_checkpoints") != 1
        or r"\.virtual_documents" in before["pattern"]
        or after["pattern"] != expected_pattern
        or after["flags_ast"] != before["flags_ast"]
    ):
        raise PipelineError(
            "scanner migration is not the exact .virtual_documents extension"
        )
    compiled = re.compile(after["pattern"], re.IGNORECASE)
    positives = (
        ".virtual_documents/use.ipynb",
        "nested/.virtual_documents/use.ipynb",
        "NESTED/.VIRTUAL_DOCUMENTS/use.ipynb",
    )
    negatives = (
        "virtual_documents/use.ipynb",
        ".virtual_documents.ipynb",
        "nested/.virtual_documents-output/use.ipynb",
    )
    if not all(compiled.search(path) for path in positives) or any(
        compiled.search(path) for path in negatives
    ):
        raise PipelineError("scanner migration generated-path boundaries changed")

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
        raise PipelineError("scanner migration network source proof changed")
    audit = {
        "version": 1,
        "predecessor_source_commit": predecessor,
        "audited_issue_commit": audited,
        "successor_source_commit": head,
        "audited_issue_commits": list(commits),
        "changed_issue_paths": list(issue_paths),
        "changed_control_paths": list(control_paths),
        "prior_network_task_source_sha256": prior_network_sha256,
        "current_network_task_source_sha256": current_network,
        "virtual_documents_positive_cases": list(positives),
        "virtual_documents_negative_cases": list(negatives),
    }
    audit["source_audit_sha256"] = _sha256(audit)
    return audit


def _assert_fingerprint_transition(
    prior: Mapping[str, Any], current: Mapping[str, Any]
) -> None:
    normalized = copy.deepcopy(dict(prior))
    current_document = copy.deepcopy(dict(current))
    try:
        normalized["filters"]["shared"] = current_document["filters"]["shared"]
        for library_id, values in normalized["libraries"].items():
            values["detector"] = current_document["libraries"][library_id][
                "detector"
            ]
    except (KeyError, TypeError) as exc:
        raise PipelineError("scanner migration fingerprints are malformed") from exc
    if normalized != current_document or dict(prior) == current_document:
        raise PipelineError(
            "scanner migration changed a non-scanner fingerprint surface"
        )


def _scan_task_key(
    row,
    payload: Mapping[str, Any],
    detectors: Mapping[str, str],
    manifest: Mapping[str, Any],
) -> str:
    libraries = tuple(payload.get("libraries") or ())
    head_sha = payload.get("head_sha")
    if (
        payload.get("full_name") is None
        or not isinstance(head_sha, str)
        or not re.fullmatch(r"[0-9a-f]{40,64}", head_sha)
        or any(library_id not in detectors for library_id in libraries)
    ):
        raise PipelineError("scanner migration task payload is malformed")
    analysis_only = not libraries
    return fingerprint(
        "scan-task-v2",
        {
            "repository_node_id": row["repository_id"],
            "head_sha": head_sha,
            "candidate_library_ids": sorted(libraries),
            "analysis_only": analysis_only,
            "ai_fingerprint": manifest.get("ai") if analysis_only else None,
            "detector_fingerprints": {
                library_id: detectors[library_id]
                for library_id in sorted(libraries)
            },
        },
    )


def authorize_phase8_scanner_source_migration(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
    reason: str,
) -> dict[str, Any]:
    """Certify and adopt the exact audited scanner issue-lane source."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason or ""):
        raise PipelineError("scanner migration reason must be machine-readable")
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError("scanner migration requires the failed cohort run")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        prior_fingerprints = json.loads(run["fingerprints_json"] or "{}")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("scanner migration run contract is malformed") from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("scanner_source_migration") is not None
    ):
        raise PipelineError("scanner migration run identity changed")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("scanner migration found a changed safety budget")

    prior_network = str(contract.get("network_task_source_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", prior_network):
        raise PipelineError("scanner migration prior network source is malformed")
    audit = _source_audit(repo_root, prior_network)
    current_fingerprint_document = current_fingerprints().as_dict()
    _assert_fingerprint_transition(
        prior_fingerprints, current_fingerprint_document
    )
    prior_detectors = _effective_detectors(prior_fingerprints)
    current_detectors = _effective_detectors(current_fingerprint_document)

    scan_tasks = state.connection.execute(
        """
        SELECT task_id,task_key,repository_id,payload_json,status
        FROM tasks WHERE run_id=? AND stage='scan' ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    if len(scan_tasks) != _TASK_UNIVERSE:
        raise PipelineError("scanner migration task universe changed")
    prior_task_keys = {str(row["task_key"]) for row in scan_tasks}
    target_task_keys: set[str] = set()
    task_key_rows = []
    for task in scan_tasks:
        try:
            payload = json.loads(task["payload_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError("scanner migration task payload is malformed") from exc
        prior_key = _scan_task_key(
            task, payload, prior_detectors, prior_fingerprints
        )
        target_key = _scan_task_key(
            task, payload, current_detectors, current_fingerprint_document
        )
        if task["task_key"] != prior_key:
            raise PipelineError("scanner migration predecessor task key changed")
        if target_key in target_task_keys or (
            target_key != prior_key and target_key in prior_task_keys
        ):
            raise PipelineError("scanner migration task key collides")
        target_task_keys.add(target_key)
        if target_key != prior_key:
            task_key_rows.append({
                "task_id": int(task["task_id"]),
                "prior_task_key": prior_key,
                "target_task_key": target_key,
                "payload_sha256": hashlib.sha256(
                    str(task["payload_json"] or "{}").encode("utf-8")
                ).hexdigest(),
            })
    if len(task_key_rows) != _TASK_UNIVERSE:
        raise PipelineError("scanner migration did not re-key the exact universe")

    completed = state.connection.execute(
        """
        SELECT task_id,task_key,repository_id,payload_json,result_json
        FROM tasks
        WHERE run_id=? AND stage='scan' AND status='complete'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    if not completed:
        raise PipelineError("scanner migration has no completed scans")
    result_document_proofs = []
    migration_rows: list[dict[str, Any]] = []
    migration_proofs = []
    target_result_identities: set[tuple[str, str, str, str]] = set()
    migrated_repositories: set[str] = set()
    for task in completed:
        try:
            document = json.loads(task["result_json"] or "{}")
            payload = json.loads(task["payload_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError("scanner migration completed result is malformed") from exc
        if _document_virtual_paths(document):
            raise PipelineError(
                "completed scan contains .virtual_documents evidence"
            )
        result_document_proofs.append({
            "task_id": int(task["task_id"]),
            "task_key": str(task["task_key"]),
            "payload_sha256": hashlib.sha256(
                str(task["payload_json"] or "{}").encode("utf-8")
            ).hexdigest(),
            "result_sha256": hashlib.sha256(
                str(task["result_json"] or "{}").encode("utf-8")
            ).hexdigest(),
        })
        head_sha = payload.get("head_sha")
        payload_libraries = tuple(payload.get("libraries") or ())
        if (
            not isinstance(head_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", head_sha)
            or not payload_libraries
            or any(item not in prior_detectors for item in payload_libraries)
        ):
            raise PipelineError("scanner migration completed payload is malformed")
        results = state.connection.execute(
            """
            SELECT scan_result_id,repository_id,library_id,head_sha,
                   detector_fp,classification,status,evidence_json,
                   raw_first_commit,raw_first_date,derived_first_date,scanned_at
            FROM scan_results
            WHERE repository_id=? AND head_sha=? AND status='clean'
            ORDER BY library_id,detector_fp,scan_result_id
            """,
            (task["repository_id"], head_sha),
        ).fetchall()
        migrated_libraries = set()
        for result in results:
            library_id = str(result["library_id"])
            if result["detector_fp"] != prior_detectors.get(library_id):
                continue
            target_detector = current_detectors.get(library_id)
            if not isinstance(target_detector, str):
                raise PipelineError("scanner migration target detector is absent")
            try:
                evidence = json.loads(result["evidence_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PipelineError("scanner migration evidence is malformed") from exc
            if _document_virtual_paths(evidence):
                raise PipelineError(
                    "completed scan evidence contains .virtual_documents"
                )
            identity = (
                str(result["repository_id"]),
                library_id,
                str(result["head_sha"]),
                target_detector,
            )
            if identity in target_result_identities or state.connection.execute(
                """
                SELECT 1 FROM scan_results
                WHERE repository_id=? AND library_id=? AND head_sha=?
                  AND detector_fp=?
                """,
                identity,
            ).fetchone() is not None:
                raise PipelineError("scanner migration target result collides")
            target_result_identities.add(identity)
            migrated = {
                key: result[key]
                for key in (
                    "repository_id",
                    "library_id",
                    "head_sha",
                    "classification",
                    "status",
                    "evidence_json",
                    "raw_first_commit",
                    "raw_first_date",
                    "derived_first_date",
                    "scanned_at",
                )
            }
            migrated["detector_fp"] = target_detector
            migration_rows.append(migrated)
            migration_proofs.append({
                "source_scan_result_id": int(result["scan_result_id"]),
                "task_id": int(task["task_id"]),
                "repository_id": str(result["repository_id"]),
                "library_id": library_id,
                "head_sha": str(result["head_sha"]),
                "prior_detector_fp": str(result["detector_fp"]),
                "target_detector_fp": target_detector,
                "row_sha256": _sha256(migrated),
            })
            migrated_libraries.add(library_id)
            migrated_repositories.add(str(result["repository_id"]))
        if not set(payload_libraries) <= migrated_libraries:
            raise PipelineError("completed scan lacks a compatible detector result")

    certified_rows = 0
    certified_repositories: set[str] = set()
    certified_sha256 = _sha256(None)
    certified_raw = contract.get("certified_scan_checkpoint")
    if certified_raw is not None:
        certified = _validate_certified_scan_checkpoint_contract(certified_raw)
        certified_sha256 = certified["certificate_sha256"]
        stage = state.connection.execute(
            """
            SELECT status,checkpoint_json FROM stages
            WHERE run_id=? AND stage='scan_checkpoint_reuse'
            """,
            (run_id,),
        ).fetchone()
        try:
            checkpoint = json.loads(
                stage["checkpoint_json"] if stage is not None else "{}"
            )
            provenance_rows = checkpoint["rows"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError("scanner checkpoint proof is malformed") from exc
        if (
            stage is None
            or stage["status"] != "complete"
            or checkpoint.get("row_count") != certified["target_row_count"]
            or len(provenance_rows) != certified["target_row_count"]
            or checkpoint.get("provenance_sha256") != _sha256(provenance_rows)
        ):
            raise PipelineError("scanner checkpoint proof changed")
        for provenance in provenance_rows:
            result_id = provenance.get("target_scan_result_id")
            if (
                not isinstance(result_id, int)
                or provenance.get("successor_run_id") != run_id
                or provenance.get("compatibility_sha256")
                != certified["certificate_sha256"]
            ):
                raise PipelineError("scanner checkpoint provenance changed")
            checkpoint_result = state.connection.execute(
                "SELECT * FROM scan_results WHERE scan_result_id=?",
                (result_id,),
            ).fetchone()
            if checkpoint_result is None:
                raise PipelineError("scanner checkpoint result is unavailable")
            library_id = str(checkpoint_result["library_id"])
            target_detector = current_detectors.get(library_id)
            if (
                checkpoint_result["status"] != "clean"
                or checkpoint_result["detector_fp"]
                != provenance.get("target_detector_fp")
                or not isinstance(target_detector, str)
            ):
                raise PipelineError("scanner checkpoint detector changed")
            result = state.connection.execute(
                """
                SELECT * FROM scan_results
                WHERE repository_id=? AND library_id=? AND head_sha=?
                  AND detector_fp=? AND status='clean'
                """,
                (
                    checkpoint_result["repository_id"],
                    library_id,
                    checkpoint_result["head_sha"],
                    prior_detectors.get(library_id),
                ),
            ).fetchone()
            if result is None:
                raise PipelineError(
                    "scanner checkpoint compatible intermediate is unavailable"
                )
            evidence = json.loads(result["evidence_json"] or "{}")
            if _document_virtual_paths(evidence):
                raise PipelineError(
                    "scanner checkpoint evidence contains .virtual_documents"
                )
            identity = (
                str(result["repository_id"]),
                library_id,
                str(result["head_sha"]),
                target_detector,
            )
            if identity in target_result_identities or state.connection.execute(
                """
                SELECT 1 FROM scan_results
                WHERE repository_id=? AND library_id=? AND head_sha=?
                  AND detector_fp=?
                """,
                identity,
            ).fetchone() is not None:
                raise PipelineError("scanner checkpoint target collides")
            target_result_identities.add(identity)
            migrated = {
                key: result[key]
                for key in (
                    "repository_id",
                    "library_id",
                    "head_sha",
                    "classification",
                    "status",
                    "evidence_json",
                    "raw_first_commit",
                    "raw_first_date",
                    "derived_first_date",
                    "scanned_at",
                )
            }
            migrated["detector_fp"] = target_detector
            migration_rows.append(migrated)
            migration_proofs.append({
                "source_scan_result_id": int(result["scan_result_id"]),
                "checkpoint_target_scan_result_id": result_id,
                "checkpoint_predecessor_task_id": provenance.get(
                    "predecessor_task_id"
                ),
                "checkpoint_compatibility_sha256": certified[
                    "certificate_sha256"
                ],
                "repository_id": str(result["repository_id"]),
                "library_id": library_id,
                "head_sha": str(result["head_sha"]),
                "prior_detector_fp": str(result["detector_fp"]),
                "target_detector_fp": target_detector,
                "row_sha256": _sha256(migrated),
            })
            migrated_repositories.add(str(result["repository_id"]))
            certified_repositories.add(str(result["repository_id"]))
            certified_rows += 1
        if certified_rows != certified["target_row_count"]:
            raise PipelineError("scanner checkpoint migration is incomplete")

    migration = {
        "version": 1,
        "kind": "phase8-audited-scanner-source-compatibility-migration",
        "policy": "exact-source-monotonic-result-preservation",
        "predecessor_source_commit": audit["predecessor_source_commit"],
        "audited_issue_commit": audit["audited_issue_commit"],
        "successor_source_commit": audit["successor_source_commit"],
        "changed_issue_paths": audit["changed_issue_paths"],
        "changed_control_paths": audit["changed_control_paths"],
        "source_audit_sha256": audit["source_audit_sha256"],
        "prior_fingerprints_sha256": _sha256(prior_fingerprints),
        "current_fingerprints_sha256": _sha256(current_fingerprint_document),
        "prior_shared_filter_sha256": prior_fingerprints["filters"]["shared"],
        "current_shared_filter_sha256": current_fingerprint_document["filters"][
            "shared"
        ],
        "prior_network_task_source_sha256": audit[
            "prior_network_task_source_sha256"
        ],
        "current_network_task_source_sha256": audit[
            "current_network_task_source_sha256"
        ],
        "task_universe_count": len(scan_tasks),
        "completed_scan_tasks_certified": len(completed),
        "completed_result_documents_sha256": _sha256(result_document_proofs),
        "completed_results_with_virtual_documents_evidence": 0,
        "certified_checkpoint_scan_result_count": certified_rows,
        "certified_checkpoint_repository_count": len(certified_repositories),
        "certified_checkpoint_certificate_sha256": certified_sha256,
        "migrated_scan_result_count": len(migration_rows),
        "migrated_repository_count": len(migrated_repositories),
        "migrated_scan_results_sha256": _sha256(migration_proofs),
        "migrated_scan_task_key_count": len(task_key_rows),
        "migrated_scan_task_keys_sha256": _sha256(task_key_rows),
        "target_detector_fingerprints_sha256": _sha256(current_detectors),
    }
    migration["contract_sha256"] = _sha256(migration)
    now = (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    updated_plan = copy.deepcopy(plan)
    updated_contract = dict(contract)
    updated_contract["network_task_source_sha256"] = audit[
        "current_network_task_source_sha256"
    ]
    updated_contract["scanner_source_migration"] = migration
    updated_plan["execution_contract"] = updated_contract
    updated_plan["fingerprints"] = current_fingerprint_document
    with state.transaction(immediate=True):
        for row in task_key_rows:
            changed = state.connection.execute(
                """
                UPDATE tasks SET task_key=?,updated_at=?
                WHERE task_id=? AND task_key=?
                """,
                (
                    row["target_task_key"],
                    now,
                    row["task_id"],
                    row["prior_task_key"],
                ),
            ).rowcount
            if changed != 1:
                raise PipelineError("scanner migration task changed concurrently")
        for migrated in migration_rows:
            state.connection.execute(
                """
                INSERT INTO scan_results(
                    repository_id,library_id,head_sha,detector_fp,
                    classification,status,evidence_json,raw_first_commit,
                    raw_first_date,derived_first_date,scanned_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    migrated["repository_id"],
                    migrated["library_id"],
                    migrated["head_sha"],
                    migrated["detector_fp"],
                    migrated["classification"],
                    migrated["status"],
                    migrated["evidence_json"],
                    migrated["raw_first_commit"],
                    migrated["raw_first_date"],
                    migrated["derived_first_date"],
                    migrated["scanned_at"],
                ),
            )
        changed_run = state.connection.execute(
            """
            UPDATE runs SET plan_json=?,fingerprints_json=?,checkpoint_at=?
            WHERE run_id=? AND status='failed'
            """,
            (
                canonical_json(updated_plan),
                canonical_json(current_fingerprint_document),
                now,
                run_id,
            ),
        ).rowcount
        if changed_run != 1:
            raise PipelineError("scanner migration run changed concurrently")
        state.update_stage(
            run_id,
            "phase8_scanner_source_migration",
            status="complete",
            counters={
                "task_universe_count": len(scan_tasks),
                "completed_scan_tasks_preserved": len(completed),
                "migrated_scan_result_count": len(migration_rows),
                "migrated_scan_task_key_count": len(task_key_rows),
            },
            metrics={
                "reset_scan_tasks": 0,
                "other_budget_changes": 0,
                "virtual_documents_evidence_count": 0,
            },
            checkpoint={
                "reason": reason,
                "authorized_at": now,
                "source_audit": audit,
                "migration": migration,
            },
        )
    return {
        "run_id": run_id,
        "status": run["status"],
        "migration": migration,
        "completed_scan_tasks_preserved": len(completed),
        "reset_scan_tasks": 0,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def _source_retry_control_audit(
    repo_root: Path,
    migration: Mapping[str, Any],
) -> dict[str, Any]:
    """Prove that only the post-migration retry control plane changed."""
    if str(_git(repo_root, "status", "--porcelain")).strip():
        raise PipelineError(
            "scanner source issue retry requires a clean tracked worktree"
        )
    source_commit = migration.get("successor_source_commit")
    if not isinstance(source_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", source_commit
    ):
        raise PipelineError("scanner source issue retry migration is malformed")
    head = str(_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_commit, head],
        cwd=repo_root,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if ancestor.returncode:
        raise PipelineError("scanner source issue retry ancestry changed")
    changed_paths = tuple(sorted(
        line
        for line in str(
            _git(
                repo_root,
                "diff",
                "--name-only",
                source_commit + ".." + head,
            )
        ).splitlines()
        if line
    ))
    required = {
        "collector/cli.py",
        "collector/phase8_source_migration.py",
        "collector/state.py",
        "test_req14_scan_attempts.py",
        "test_req14_successor.py",
    }
    if (
        not required <= set(changed_paths)
        or set(changed_paths) - _SOURCE_RETRY_CONTROL_PATHS
    ):
        raise PipelineError(
            "scanner source issue retry control path set changed"
        )
    audit = {
        "version": 1,
        "scanner_migration_source_commit": source_commit,
        "retry_control_source_commit": head,
        "changed_control_paths": list(changed_paths),
    }
    audit["source_audit_sha256"] = _sha256(audit)
    return audit


def _recover_exact_stale_coordinator_attempt(
    *,
    state: StateDB,
    run_id: str,
    budgets: RunBudgets,
    fingerprints: Mapping[str, Any],
    base_release_id: str | None,
    contract: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Apply normal compatible-resume semantics to the one stale lease."""
    rows = state.connection.execute(
        """
        SELECT t.task_id,t.task_key,t.repository_id,t.payload_json,t.status,
               t.error_code,t.attempts,t.max_attempts,
               sa.status AS attempt_status,sa.retryable,
               sa.error_code AS attempt_error_code,sa.error_detail,
               sa.usage_complete
        FROM tasks t
        JOIN repositories r ON r.node_id=t.repository_id
        JOIN scan_attempts sa
          ON sa.task_id=CAST(t.task_id AS TEXT) AND sa.attempt=t.attempts
        WHERE t.run_id=? AND t.stage='scan' AND t.status='running'
        ORDER BY t.task_id
        """,
        (run_id,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise PipelineError(
            "scanner source issue retry found multiple stale scan attempts"
        )
    row = rows[0]
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "scanner source issue retry stale payload is malformed"
        ) from exc
    incident = _STALE_COORDINATOR_INCIDENT
    if (
        payload.get("full_name") != incident["full_name"]
        or payload.get("head_sha") != incident["head_sha"]
        or tuple(payload.get("libraries") or ()) != incident["libraries"]
        or int(row["attempts"]) != incident["attempts"]
        or int(row["max_attempts"]) != incident["max_attempts"]
        or row["error_code"] != "repository_timeout"
        or row["attempt_status"] != "running"
        or row["retryable"] is not None
        or row["attempt_error_code"] is not None
        or row["error_detail"] is not None
        or int(row["usage_complete"] or 0) != 0
    ):
        raise PipelineError(
            "scanner source issue retry stale attempt proof changed"
        )
    resumed = state.resume_compatible_run(
        mode="reconcile",
        budgets=budgets.to_dict(),
        fingerprints=fingerprints,
        base_release_id=base_release_id,
        execution_contract=contract,
    )
    if resumed != run_id:
        raise PipelineError(
            "scanner source issue retry could not recover the failed run"
        )
    state.finish_run(run_id, status="failed")
    recovered_attempt = state.connection.execute(
        """
        SELECT status,retryable,error_code,usage_complete
        FROM scan_attempts WHERE task_id=? AND attempt=?
        """,
        (str(row["task_id"]), incident["attempts"]),
    ).fetchone()
    recovered_task = state.connection.execute(
        "SELECT status,error_code FROM tasks WHERE task_id=?",
        (row["task_id"],),
    ).fetchone()
    if (
        recovered_attempt is None
        or recovered_attempt["status"] != "interrupted"
        or recovered_attempt["retryable"] != 1
        or recovered_attempt["error_code"] != "coordinator_interrupted"
        or recovered_attempt["usage_complete"] != 0
        or recovered_task is None
        or recovered_task["status"] != "failed"
        or recovered_task["error_code"] != "resume_scan_usage_unknown"
    ):
        raise PipelineError(
            "scanner source issue retry stale recovery changed"
        )
    return {
        "task_id": int(row["task_id"]),
        "task_key": str(row["task_key"]),
        "repository_id": str(row["repository_id"]),
        "full_name": incident["full_name"],
        "head_sha": incident["head_sha"],
        "attempt": incident["attempts"],
        "accounting": "usage_unknown_never_zero",
        "error_code": "coordinator_interrupted",
    }


def _migrate_prior_issue_retry_certificates(
    *,
    state: StateDB,
    run_id: str,
    migration: Mapping[str, Any],
) -> dict[str, Any]:
    """Carry reviewed retry identities through the audited all-task re-key."""
    contract_sha256 = migration["contract_sha256"]
    migrated: dict[str, int] = {}
    for stage_name in (
        "phase8_issue_retry",
        "phase8_buildozer_issue_retry",
    ):
        stage = state.connection.execute(
            """
            SELECT status,counters_json,metrics_json,checkpoint_json
            FROM stages WHERE run_id=? AND stage=?
            """,
            (run_id, stage_name),
        ).fetchone()
        if stage is None or stage["status"] != "complete":
            raise PipelineError(
                "scanner source issue retry prior certificate is absent"
            )
        try:
            counters = json.loads(stage["counters_json"] or "{}")
            metrics = json.loads(stage["metrics_json"] or "{}")
            checkpoint = json.loads(stage["checkpoint_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "scanner source issue retry prior certificate is malformed"
            ) from exc
        prior_migration = checkpoint.get("scanner_source_task_key_migration")
        if prior_migration is not None:
            if (
                not isinstance(prior_migration, Mapping)
                or prior_migration.get("scanner_migration_contract_sha256")
                != contract_sha256
                or prior_migration.get("migrated_task_count")
                != checkpoint.get("reset_task_count")
            ):
                raise PipelineError(
                    "scanner source issue retry prior re-key proof changed"
                )
            migrated[stage_name] = int(
                prior_migration["migrated_task_count"]
            )
            continue
        if stage_name == "phase8_issue_retry":
            selected = checkpoint.get("selected_tasks")
            if (
                not isinstance(selected, list)
                or checkpoint.get("selection_sha256") != _sha256(selected)
                or checkpoint.get("reset_task_count") != len(selected)
                or len(selected) != 17
                or checkpoint.get("other_budget_changes") != 0
            ):
                raise PipelineError(
                    "scanner source issue retry typed certificate changed"
                )
            prior_sha256 = checkpoint["selection_sha256"]
            updated = copy.deepcopy(selected)
            for item in updated:
                task = state.connection.execute(
                    """
                    SELECT task_key,repository_id FROM tasks
                    WHERE run_id=? AND stage='scan' AND task_id=?
                    """,
                    (run_id, item.get("task_id")),
                ).fetchone()
                if (
                    task is None
                    or task["repository_id"] != item.get("repository_id")
                    or not isinstance(item.get("task_key"), str)
                    or task["task_key"] == item["task_key"]
                ):
                    raise PipelineError(
                        "scanner source issue retry typed task key changed"
                    )
                item["prior_task_key"] = item["task_key"]
                item["task_key"] = str(task["task_key"])
            checkpoint["selected_tasks"] = updated
            checkpoint["selection_sha256"] = _sha256(updated)
            migrated_count = len(updated)
            current_sha256 = checkpoint["selection_sha256"]
        else:
            task = state.connection.execute(
                """
                SELECT task_key FROM tasks
                WHERE run_id=? AND stage='scan' AND task_id=?
                """,
                (run_id, checkpoint.get("task_id")),
            ).fetchone()
            if (
                checkpoint.get("version") != 1
                or checkpoint.get("reset_task_count") != 1
                or checkpoint.get("other_budget_changes") != 0
                or task is None
                or not isinstance(checkpoint.get("task_key"), str)
                or task["task_key"] == checkpoint["task_key"]
            ):
                raise PipelineError(
                    "scanner source issue retry buildozer certificate changed"
                )
            prior_sha256 = _sha256({
                "task_id": checkpoint["task_id"],
                "task_key": checkpoint["task_key"],
            })
            checkpoint["prior_task_key"] = checkpoint["task_key"]
            checkpoint["task_key"] = str(task["task_key"])
            migrated_count = 1
            current_sha256 = _sha256({
                "task_id": checkpoint["task_id"],
                "task_key": checkpoint["task_key"],
            })
        checkpoint["scanner_source_task_key_migration"] = {
            "version": 1,
            "scanner_migration_contract_sha256": contract_sha256,
            "migrated_task_count": migrated_count,
            "prior_certificate_sha256": prior_sha256,
            "current_certificate_sha256": current_sha256,
        }
        state.update_stage(
            run_id,
            stage_name,
            status="complete",
            counters=counters,
            metrics=metrics,
            checkpoint=checkpoint,
        )
        migrated[stage_name] = migrated_count
    if migrated != {
        "phase8_buildozer_issue_retry": 1,
        "phase8_issue_retry": 17,
    }:
        raise PipelineError(
            "scanner source issue retry prior certificate universe changed"
        )
    return {
        "version": 1,
        "scanner_migration_contract_sha256": contract_sha256,
        "migrated_certificates": dict(sorted(migrated.items())),
        "migrated_task_count": sum(migrated.values()),
    }


def authorize_phase8_scanner_source_issue_retry(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
    reason: str,
) -> dict[str, Any]:
    """Requeue only the four incidents fixed by the audited source migration."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason or ""):
        raise PipelineError(
            "scanner source issue retry reason must be machine-readable"
        )
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,
               base_release_id,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] != "failed":
        raise PipelineError(
            "scanner source issue retry requires the failed cohort run"
        )
    try:
        plan = json.loads(run["plan_json"] or "{}")
        contract = dict(plan["execution_contract"])
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        migration = dict(contract["scanner_source_migration"])
        selected_library_ids = set(contract["selected_library_ids"])
        metadata_batch_size = int(contract["metadata_batch_size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "scanner source issue retry run contract is malformed"
        ) from exc
    current = current_fingerprints().as_dict()
    reviewed = _validate_reviewed_execution_contract(
        contract,
        mode="reconcile",
        wanted=selected_library_ids,
        budgets=budgets,
        metadata_batch_size=metadata_batch_size,
    )
    if reviewed is None or fingerprints != current:
        raise PipelineError(
            "scanner source issue retry execution contract is incompatible"
        )
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall < actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError(
            "scanner source issue retry found a changed safety budget"
        )
    migration_stage = state.connection.execute(
        """
        SELECT status,checkpoint_json FROM stages
        WHERE run_id=? AND stage='phase8_scanner_source_migration'
        """,
        (run_id,),
    ).fetchone()
    try:
        migration_checkpoint = json.loads(
            migration_stage["checkpoint_json"]
            if migration_stage is not None else "{}"
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "scanner source issue retry migration checkpoint is malformed"
        ) from exc
    if (
        migration_stage is None
        or migration_stage["status"] != "complete"
        or migration_checkpoint.get("migration") != migration
        or migration.get("contract_sha256") != _sha256({
            key: value
            for key, value in migration.items()
            if key != "contract_sha256"
        })
        or migration.get("task_universe_count") != _TASK_UNIVERSE
        or migration.get("completed_results_with_virtual_documents_evidence")
        != 0
    ):
        raise PipelineError(
            "scanner source issue retry migration proof changed"
        )
    if state.connection.execute(
        """
        SELECT 1 FROM stages
        WHERE run_id=? AND stage='phase8_scanner_source_issue_retry'
        """,
        (run_id,),
    ).fetchone() is not None:
        raise PipelineError("scanner source issue retry was already applied")
    source_audit = _source_retry_control_audit(repo_root, migration)
    detectors = _effective_detectors(current)
    selected: list[dict[str, Any]] = []
    for expected in _SOURCE_RETRY_INCIDENTS:
        rows = state.connection.execute(
            """
            SELECT t.task_id,t.task_key,t.repository_id,t.payload_json,
                   t.status,t.error_code AS task_error_code,t.attempts,
                   t.max_attempts,sa.task_key AS attempt_task_key,
                   sa.payload_sha256,sa.status AS attempt_status,
                   sa.retryable,sa.error_code AS attempt_error_code,
                   sa.error_detail,sa.usage_complete
            FROM tasks t
            JOIN repositories r ON r.node_id=t.repository_id
            JOIN scan_attempts sa
              ON sa.task_id=CAST(t.task_id AS TEXT)
             AND sa.attempt=t.attempts
            WHERE t.run_id=? AND t.stage='scan' AND r.full_name=?
            """,
            (run_id, expected["full_name"]),
        ).fetchall()
        if len(rows) != 1:
            raise PipelineError(
                "scanner source issue retry incident identity changed"
            )
        row = rows[0]
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError(
                "scanner source issue retry payload is malformed"
            ) from exc
        payload_sha256 = hashlib.sha256(
            str(row["payload_json"] or "{}").encode("utf-8")
        ).hexdigest()
        expected_task_key = _scan_task_key(
            row, payload, detectors, current
        )
        if (
            row["status"] != "failed"
            or row["task_key"] != expected_task_key
            or payload.get("full_name") != expected["full_name"]
            or payload.get("head_sha") != expected["head_sha"]
            or tuple(payload.get("libraries") or ()) != expected["libraries"]
            or row["task_error_code"] != expected["task_error_code"]
            or int(row["attempts"]) != expected["attempts"]
            or int(row["max_attempts"]) != expected["max_attempts"]
            or row["attempt_status"] != "failed"
            or bool(row["retryable"]) != expected["retryable"]
            or row["attempt_error_code"] != expected["attempt_error_code"]
            or row["error_detail"] != expected["error_detail"]
            or int(row["usage_complete"] or 0) != 1
            or row["payload_sha256"] != payload_sha256
        ):
            raise PipelineError(
                "scanner source issue retry incident proof changed"
            )
        selected.append({
            "task_id": int(row["task_id"]),
            "task_key": str(row["task_key"]),
            "attempt_task_key": str(row["attempt_task_key"]),
            "repository_id": str(row["repository_id"]),
            "full_name": expected["full_name"],
            "head_sha": expected["head_sha"],
            "libraries": list(expected["libraries"]),
            "payload_sha256": payload_sha256,
            "prior_attempts": expected["attempts"],
            "prior_max_attempts": expected["max_attempts"],
            "target_max_attempts": expected["attempts"] + 1,
            "prior_error_code": expected["attempt_error_code"],
            "prior_error_detail": expected["error_detail"],
            "remediation": expected["remediation"],
            "policy": "audited_scanner_source_migration",
        })
    selected.sort(key=lambda item: item["task_id"])
    if len(selected) != len(_SOURCE_RETRY_INCIDENTS):
        raise PipelineError("scanner source issue retry selection changed")
    completed_before = int(state.connection.execute(
        """
        SELECT COUNT(*) FROM tasks
        WHERE run_id=? AND stage='scan' AND status='complete'
        """,
        (run_id,),
    ).fetchone()[0])
    task_universe = int(state.connection.execute(
        """
        SELECT COUNT(*) FROM tasks WHERE run_id=? AND stage='scan'
        """,
        (run_id,),
    ).fetchone()[0])
    if (
        task_universe != _TASK_UNIVERSE
        or completed_before != migration.get("completed_scan_tasks_certified")
    ):
        raise PipelineError(
            "scanner source issue retry compatible completion set changed"
        )
    prior_retry_migration = _migrate_prior_issue_retry_certificates(
        state=state,
        run_id=run_id,
        migration=migration,
    )
    stale_recovery = _recover_exact_stale_coordinator_attempt(
        state=state,
        run_id=run_id,
        budgets=budgets,
        fingerprints=fingerprints,
        base_release_id=run["base_release_id"],
        contract=contract,
    )
    usage = _scan_attempt_usage_for_run(state, run_id)
    _enforce_scan_attempt_budgets(
        usage,
        planned_attempts=len(selected),
        budgets=budgets,
    )
    now = (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    selection_sha256 = _sha256(selected)
    checkpoint = {
        "version": 1,
        "reason": reason,
        "authorized_at": now,
        "source_audit": source_audit,
        "prior_issue_retry_task_key_migration": prior_retry_migration,
        "stale_coordinator_recovery": stale_recovery,
        "scanner_migration_contract_sha256": migration["contract_sha256"],
        "selection_sha256": selection_sha256,
        "selected_tasks": selected,
        "reset_task_count": len(selected),
        "completed_scan_tasks_preserved": completed_before,
        "task_universe_count": task_universe,
        "other_budget_changes": 0,
    }
    with state.transaction(immediate=True):
        for item in selected:
            changed = state.connection.execute(
                """
                UPDATE tasks SET status='pending',max_attempts=?,
                    lease_owner=NULL,lease_expires_at=NULL,available_at=0,
                    error_code=?,updated_at=?,finished_at=NULL
                WHERE task_id=? AND status='failed' AND attempts=?
                  AND max_attempts=? AND task_key=?
                """,
                (
                    item["target_max_attempts"],
                    _SOURCE_RETRY_MARKER,
                    now,
                    item["task_id"],
                    item["prior_attempts"],
                    item["prior_max_attempts"],
                    item["task_key"],
                ),
            ).rowcount
            if changed != 1:
                raise PipelineError(
                    "scanner source issue retry task changed during control"
                )
        state.update_stage(
            run_id,
            "phase8_scanner_source_issue_retry",
            status="complete",
            counters={
                "reset_task_count": len(selected),
                "completed_scan_tasks_preserved": completed_before,
                "task_universe_count": task_universe,
            },
            metrics={"other_budget_changes": 0},
            checkpoint=checkpoint,
        )
    return {
        "run_id": run_id,
        "status": run["status"],
        "reset_task_count": len(selected),
        "selection_sha256": selection_sha256,
        "selected_repositories": [
            item["full_name"] for item in selected
        ],
        "completed_scan_tasks_preserved": completed_before,
        "task_universe_count": task_universe,
        "other_budget_changes": 0,
        "prior_issue_retry_task_keys_migrated": prior_retry_migration[
            "migrated_task_count"
        ],
        "stale_coordinator_attempts_recovered": int(
            stale_recovery is not None
        ),
        "launchd_armed": False,
    }
