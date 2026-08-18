"""Incident-only Phase 8 controls that do not alter evidence semantics.

The production cohort run is immutable by default.  The owner may authorize a
larger *overall wall clock* after production timing evidence shows that the
reviewed 36-hour ceiling is too short.  This module proves that every other
budget, detector fingerprint, discovery task, and metadata task stayed exact
before updating that one control value in place.  Completed scan tasks and
their attempt ledger are never reset or copied.
"""

from __future__ import annotations

import ast
import copy
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping

from .fingerprints import canonical_json, fingerprint
from .pipeline import (
    PHASE8_MAX_OWNER_WALL_SECONDS,
    PipelineError,
    RunBudgets,
    _enforce_scan_attempt_budgets,
    _network_task_source_sha256,
    _phase8_runtime_issue_contract,
    _scan_attempt_usage_for_run,
)
from .planner import current_fingerprints
from .state import StateDB
from .successor import (
    _CURRENT_NETWORK_TASK_PATHS,
    _assert_exact_network_task_semantics,
    _git,
    _source_payload_sha256,
    _validate_certified_scan_checkpoint_contract,
)


_WALL_EXTENSION_ALLOWED_PATHS = frozenset({
    "AGENTS.md",
    "collector/cli.py",
    "collector/config.py",
    "collector/phase8_control.py",
    "collector/phase8_issue_lane.py",
    "collector/pipeline.py",
    "collector/state.py",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "docs/REQ14-V2-REVISION.md",
    "test_req14_content_successor.py",
    "test_req14_historical_scan_usage.py",
    "test_req14_pipeline.py",
    "test_req14_scan_attempts.py",
    "test_req14_scanner.py",
    "test_req14_successor.py",
})

_TRANSIENT_SCAN_ISSUES = frozenset({
    "repository_cancelled",
    "repository_cache_integrity",
    "repository_git_timeout",
    "repository_timeout",
    "repository_transport",
})
_BUILDOZER_SEGMENT_RE = re.compile(r"(?:\A|/)\.buildozer/", re.IGNORECASE)
_BUILDOZER_REPOSITORY = "Silian1234/shootAnalyzer"


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _compiled_regex_declaration(source: bytes, name: str) -> dict[str, str]:
    """Extract one module-level ``re.compile`` declaration without importing it."""
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PipelineError("approved filter source is not parseable") from exc
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        value = node.value
        if (
            not isinstance(value, ast.Call)
            or not isinstance(value.func, ast.Attribute)
            or not isinstance(value.func.value, ast.Name)
            or value.func.value.id != "re"
            or value.func.attr != "compile"
            or not value.args
            or not isinstance(value.args[0], ast.Constant)
            or not isinstance(value.args[0].value, str)
        ):
            break
        flags = ast.dump(value.args[1], include_attributes=False) if len(value.args) > 1 else ""
        return {"pattern": value.args[0].value, "flags_ast": flags}
    raise PipelineError("approved filter declaration is unavailable")


def _approved_buildozer_source_change(
    root: Path,
    predecessor_commit: str,
) -> dict[str, Any] | None:
    predecessor = bytes(
        _git(
            root,
            "show",
            predecessor_commit + ":collector/config.py",
            text=False,
        )
    )
    current = (root / "collector/config.py").read_bytes()
    if predecessor == current:
        return None
    before = _compiled_regex_declaration(predecessor, "ENV_DUMP_PATH_RE")
    after = _compiled_regex_declaration(current, "ENV_DUMP_PATH_RE")
    expected = before["pattern"].replace(
        r"\.conda|", r"\.conda|\.buildozer|", 1
    )
    if (
        before["pattern"].count(r"\.conda|") != 1
        or r"\.buildozer" in before["pattern"]
        or after["pattern"] != expected
        or after["flags_ast"] != before["flags_ast"]
    ):
        raise PipelineError(
            "config change is not the approved exact .buildozer segment exclusion"
        )
    compiled = re.compile(after["pattern"], re.IGNORECASE)
    positives = (
        ".buildozer/source/use.cu",
        "nested/.buildozer/source/use.cu",
        "NESTED/.BUILDOZER/source/use.cu",
    )
    negatives = (
        "buildozer.spec",
        "src/buildozer/use.cu",
        ".buildozer.spec/use.cu",
        "src/.buildozer-output/use.cu",
        "src/prefix.buildozer/use.cu",
    )
    if not all(compiled.search(path) for path in positives) or any(
        compiled.search(path) for path in negatives
    ):
        raise PipelineError("approved .buildozer segment boundaries changed")
    return {
        "version": 1,
        "directory_segment": ".buildozer",
        "policy": "exact-generated-directory-monotonic-exclusion",
        "predecessor_config_sha256": hashlib.sha256(predecessor).hexdigest(),
        "successor_config_sha256": hashlib.sha256(current).hexdigest(),
        "predecessor_pattern_sha256": hashlib.sha256(
            before["pattern"].encode("utf-8")
        ).hexdigest(),
        "successor_pattern_sha256": hashlib.sha256(
            after["pattern"].encode("utf-8")
        ).hexdigest(),
        "positive_boundary_cases": list(positives),
        "negative_boundary_cases": list(negatives),
    }


def _document_buildozer_paths(value: Any) -> list[str]:
    matches: list[str] = []
    if isinstance(value, Mapping):
        for nested in value.values():
            matches.extend(_document_buildozer_paths(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            matches.extend(_document_buildozer_paths(nested))
    elif isinstance(value, str) and _BUILDOZER_SEGMENT_RE.search(value):
        matches.append(value)
    return matches


def _git_tree_paths(git_dir: Path, head_sha: str) -> tuple[str, ...]:
    result = subprocess.run(
        [
            "git", "--git-dir", str(git_dir), "-c", "core.quotePath=false",
            "ls-tree", "-r", "-z", "--name-only", head_sha,
        ],
        capture_output=True,
        check=False,
        env={**__import__("os").environ, "GIT_NO_LAZY_FETCH": "1"},
        timeout=180,
    )
    if result.returncode or (result.stdout and not result.stdout.endswith(b"\0")):
        raise PipelineError("approved .buildozer Git tree is unavailable locally")
    return tuple(
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.rstrip(b"\0").split(b"\0")
        if item
    )


def _casefold_prefix_collisions(paths: tuple[str, ...]) -> tuple[dict[str, str], ...]:
    files_by_fold: dict[str, list[str]] = {}
    for path in paths:
        files_by_fold.setdefault(path.casefold(), []).append(path)
    collisions = set()
    for descendant in paths:
        parts = descendant.split("/")
        for end in range(1, len(parts)):
            directory = "/".join(parts[:end])
            for tracked_file in files_by_fold.get(directory.casefold(), ()):
                if tracked_file != directory:
                    collisions.add((tracked_file, directory, descendant))
    return tuple(
        {
            "tracked_file": tracked_file,
            "colliding_directory": directory,
            "descendant": descendant,
        }
        for tracked_file, directory, descendant in sorted(collisions)
    )


def _certify_buildozer_filter_extension(
    *,
    state: StateDB,
    run_id: str,
    prior_fingerprints: Mapping[str, Any],
    current_fingerprints_document: Mapping[str, Any],
    source_proof: Mapping[str, Any],
    cache_root: Path,
) -> tuple[
    dict[str, Any],
    tuple[dict[str, Any], ...],
    tuple[dict[str, Any], ...],
]:
    prior = copy.deepcopy(dict(prior_fingerprints))
    current = copy.deepcopy(dict(current_fingerprints_document))
    prior_shared = ((prior.get("filters") or {}).get("shared"))
    current_shared = ((current.get("filters") or {}).get("shared"))
    if not all(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
        for value in (prior_shared, current_shared)
    ):
        raise PipelineError("approved filter fingerprints are malformed")
    normalized_prior = copy.deepcopy(prior)
    normalized_prior.setdefault("filters", {})["shared"] = current_shared
    if normalized_prior != current or prior_shared == current_shared:
        raise PipelineError(
            "approved .buildozer migration requires only the shared filter change"
        )

    def effective_detectors(document: Mapping[str, Any]) -> dict[str, str]:
        libraries = document.get("libraries") or {}
        filters = document.get("filters") or {}
        shared = filters.get("shared")
        if not isinstance(libraries, Mapping) or not isinstance(shared, str):
            raise PipelineError("approved filter fingerprints are malformed")
        values = {}
        for library_id, library_fingerprints in libraries.items():
            if not isinstance(library_fingerprints, Mapping):
                raise PipelineError(
                    "approved library fingerprints are malformed"
                )
            detector = library_fingerprints.get("detector")
            if not isinstance(detector, str):
                raise PipelineError(
                    "approved library detector fingerprint is malformed"
                )
            filter_values = {"shared": shared}
            if library_id == "nvpl":
                nvpl = filters.get("nvpl")
                if not isinstance(nvpl, str):
                    raise PipelineError(
                        "approved NVPL filter fingerprint is malformed"
                    )
                filter_values["nvpl"] = nvpl
            values[str(library_id)] = fingerprint(
                "library:%s:effective-detector" % library_id,
                {"detector": detector, "filters": filter_values},
            )
        return values

    prior_detectors = effective_detectors(prior)
    current_detectors = effective_detectors(current)
    scan_task_key_rows = []
    target_task_keys = set()
    scan_tasks = state.connection.execute(
        """
        SELECT task_id,task_key,repository_id,payload_json
        FROM tasks WHERE run_id=? AND stage='scan'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    prior_task_keys = {str(row["task_key"]) for row in scan_tasks}
    for scan_task in scan_tasks:
        try:
            payload = json.loads(scan_task["payload_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError("scan task payload is malformed") from exc
        head_sha = payload.get("head_sha")
        libraries = tuple(payload.get("libraries") or ())
        if (
            payload.get("full_name") is None
            or not isinstance(head_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", head_sha)
            or any(library_id not in prior_detectors for library_id in libraries)
        ):
            raise PipelineError("scan task payload is malformed")

        def task_key(detectors: Mapping[str, str], manifest: Mapping[str, Any]):
            analysis_only = not libraries
            return fingerprint(
                "scan-task-v2",
                {
                    "repository_node_id": scan_task["repository_id"],
                    "head_sha": head_sha,
                    "candidate_library_ids": sorted(libraries),
                    "analysis_only": analysis_only,
                    "ai_fingerprint": (
                        manifest.get("ai") if analysis_only else None
                    ),
                    "detector_fingerprints": {
                        library_id: detectors[library_id]
                        for library_id in sorted(libraries)
                    },
                },
            )

        prior_task_key = task_key(prior_detectors, prior)
        target_task_key = task_key(current_detectors, current)
        if scan_task["task_key"] != prior_task_key:
            raise PipelineError(
                "scan task key does not match the certified predecessor"
            )
        if target_task_key in target_task_keys:
            raise PipelineError("scan task key migration collides")
        if (
            target_task_key != prior_task_key
            and target_task_key in prior_task_keys
        ):
            raise PipelineError(
                "scan task key migration collides with predecessor work"
            )
        target_task_keys.add(target_task_key)
        if target_task_key != prior_task_key:
            scan_task_key_rows.append({
                "task_id": int(scan_task["task_id"]),
                "prior_task_key": prior_task_key,
                "target_task_key": target_task_key,
                "payload_sha256": hashlib.sha256(
                    str(scan_task["payload_json"] or "{}").encode("utf-8")
                ).hexdigest(),
            })
    if not scan_task_key_rows:
        raise PipelineError("approved filter migration changed no scan task keys")
    completed = state.connection.execute(
        """
        SELECT task_id,task_key,repository_id,payload_json,result_json
        FROM tasks
        WHERE run_id=? AND stage='scan' AND status='complete'
        ORDER BY task_id
        """,
        (run_id,),
    ).fetchall()
    result_proofs = []
    migration_rows: list[dict[str, Any]] = []
    migration_proofs = []
    migrated_repositories = set()
    for row in completed:
        try:
            document = json.loads(row["result_json"] or "{}")
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PipelineError("completed scan result is malformed") from exc
        if _document_buildozer_paths(document):
            raise PipelineError(
                "completed scan contains .buildozer evidence and cannot be preserved"
            )
        result_proofs.append({
            "task_id": int(row["task_id"]),
            "task_key": str(row["task_key"]),
            "payload_sha256": hashlib.sha256(
                str(row["payload_json"] or "{}").encode("utf-8")
            ).hexdigest(),
            "result_sha256": hashlib.sha256(
                str(row["result_json"] or "{}").encode("utf-8")
            ).hexdigest(),
        })
        head_sha = payload.get("head_sha")
        payload_libraries = tuple(payload.get("libraries") or ())
        if (
            not isinstance(head_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", head_sha)
            or not payload_libraries
            or any(library_id not in prior_detectors for library_id in payload_libraries)
        ):
            raise PipelineError("completed scan payload is malformed")
        rows = state.connection.execute(
            """
            SELECT scan_result_id,repository_id,library_id,head_sha,
                   detector_fp,classification,status,evidence_json,
                   raw_first_commit,raw_first_date,derived_first_date,
                   scanned_at
            FROM scan_results
            WHERE repository_id=? AND head_sha=? AND status='clean'
            ORDER BY library_id,detector_fp,scan_result_id
            """,
            (row["repository_id"], head_sha),
        ).fetchall()
        migrated_payload_libraries = set()
        for result in rows:
            library_id = str(result["library_id"])
            if result["detector_fp"] != prior_detectors.get(library_id):
                continue
            target_detector = current_detectors.get(library_id)
            if not isinstance(target_detector, str):
                raise PipelineError(
                    "completed scan names an inactive detector"
                )
            try:
                evidence = json.loads(result["evidence_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PipelineError(
                    "completed scan evidence is malformed"
                ) from exc
            if _document_buildozer_paths(evidence):
                raise PipelineError(
                    "completed scan contains .buildozer evidence and cannot be preserved"
                )
            conflict = state.connection.execute(
                """
                SELECT 1 FROM scan_results
                WHERE repository_id=? AND library_id=? AND head_sha=?
                  AND detector_fp=?
                """,
                (
                    result["repository_id"],
                    library_id,
                    result["head_sha"],
                    target_detector,
                ),
            ).fetchone()
            if conflict is not None:
                raise PipelineError(
                    "approved filter migration target row already exists"
                )
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
                "task_id": int(row["task_id"]),
                "repository_id": str(result["repository_id"]),
                "library_id": library_id,
                "head_sha": str(result["head_sha"]),
                "prior_detector_fp": str(result["detector_fp"]),
                "target_detector_fp": target_detector,
                "row_sha256": _sha256(migrated),
            })
            migrated_repositories.add(str(result["repository_id"]))
            migrated_payload_libraries.add(library_id)
        if not set(payload_libraries) <= migrated_payload_libraries:
            raise PipelineError(
                "completed scan lacks a certified detector result"
            )

    run_plan_row = state.connection.execute(
        "SELECT plan_json FROM runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    try:
        run_plan = json.loads(run_plan_row["plan_json"] or "{}")
        certified_raw = (
            (run_plan.get("execution_contract") or {}).get(
                "certified_scan_checkpoint"
            )
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "certified scan checkpoint plan is malformed"
        ) from exc
    certified_checkpoint_rows = 0
    certified_checkpoint_repositories = set()
    certified_checkpoint_sha256 = _sha256(None)
    if certified_raw is not None:
        certified = _validate_certified_scan_checkpoint_contract(
            certified_raw
        )
        certified_checkpoint_sha256 = certified["certificate_sha256"]
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
            raise PipelineError(
                "certified scan checkpoint materialization is malformed"
            ) from exc
        if (
            stage is None
            or stage["status"] != "complete"
            or checkpoint.get("row_count") != certified["target_row_count"]
            or len(provenance_rows) != certified["target_row_count"]
            or checkpoint.get("provenance_sha256")
            != _sha256(provenance_rows)
        ):
            raise PipelineError(
                "certified scan checkpoint materialization changed"
            )
        seen_target_ids = set()
        for provenance in provenance_rows:
            target_id = provenance.get("target_scan_result_id")
            if (
                not isinstance(target_id, int)
                or isinstance(target_id, bool)
                or target_id <= 0
                or target_id in seen_target_ids
                or provenance.get("successor_run_id") != run_id
                or provenance.get("compatibility_sha256")
                != certified["certificate_sha256"]
            ):
                raise PipelineError(
                    "certified scan checkpoint provenance changed"
                )
            seen_target_ids.add(target_id)
            result = state.connection.execute(
                "SELECT * FROM scan_results WHERE scan_result_id=?",
                (target_id,),
            ).fetchone()
            if result is None:
                raise PipelineError(
                    "certified scan checkpoint result is unavailable"
                )
            library_id = str(result["library_id"])
            target_detector = current_detectors.get(library_id)
            if (
                result["status"] != "clean"
                or result["detector_fp"]
                != provenance.get("target_detector_fp")
                or result["detector_fp"] != prior_detectors.get(library_id)
                or not isinstance(target_detector, str)
            ):
                raise PipelineError(
                    "certified scan checkpoint detector identity changed"
                )
            try:
                evidence = json.loads(result["evidence_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PipelineError(
                    "certified scan checkpoint evidence is malformed"
                ) from exc
            if _document_buildozer_paths(evidence):
                raise PipelineError(
                    "certified scan checkpoint contains .buildozer evidence"
                )
            conflict = state.connection.execute(
                """
                SELECT 1 FROM scan_results
                WHERE repository_id=? AND library_id=? AND head_sha=?
                  AND detector_fp=?
                """,
                (
                    result["repository_id"],
                    library_id,
                    result["head_sha"],
                    target_detector,
                ),
            ).fetchone()
            if conflict is not None:
                raise PipelineError(
                    "certified checkpoint filter target already exists"
                )
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
                "source_scan_result_id": target_id,
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
            certified_checkpoint_repositories.add(
                str(result["repository_id"])
            )
            certified_checkpoint_rows += 1
        if certified_checkpoint_rows != certified["target_row_count"]:
            raise PipelineError(
                "certified scan checkpoint migration is incomplete"
            )

    task = state.connection.execute(
        """
        SELECT t.task_id,t.task_key,t.status,t.attempts,t.max_attempts,
               t.error_code,t.payload_json,r.node_id,r.full_name,r.head_sha,
               r.visibility,r.is_fork,r.is_archived,sa.status AS attempt_status,
               sa.error_code AS attempt_error_code,sa.usage_complete
        FROM tasks t JOIN repositories r ON r.node_id=t.repository_id
        JOIN scan_attempts sa
          ON sa.task_id=CAST(t.task_id AS TEXT) AND sa.attempt=t.attempts
        WHERE t.run_id=? AND t.stage='scan' AND lower(r.full_name)=lower(?)
        """,
        (run_id, _BUILDOZER_REPOSITORY),
    ).fetchone()
    if task is None:
        raise PipelineError("approved .buildozer incident task is unavailable")
    payload = json.loads(task["payload_json"] or "{}")
    if (
        task["full_name"] != _BUILDOZER_REPOSITORY
        or task["visibility"] != "public"
        or int(task["is_fork"]) != 0
        or int(task["is_archived"]) != 0
        or task["status"] != "failed"
        or task["error_code"] != "detector_error"
        or task["attempt_status"] != "failed"
        or task["attempt_error_code"] != "detector_error"
        or int(task["usage_complete"] or 0) != 1
        or int(task["attempts"]) < 1
        or payload.get("full_name") != task["full_name"]
        or payload.get("head_sha") != task["head_sha"]
        or not payload.get("libraries")
    ):
        raise PipelineError("approved .buildozer incident identity changed")
    repo_key = hashlib.sha256(task["full_name"].casefold().encode()).hexdigest()
    paths = _git_tree_paths(
        cache_root / "repos" / (repo_key + ".git"),
        str(task["head_sha"]),
    )
    buildozer_paths = tuple(
        path for path in paths if _BUILDOZER_SEGMENT_RE.search(path)
    )
    collisions = _casefold_prefix_collisions(buildozer_paths)
    if not buildozer_paths or not collisions:
        raise PipelineError(
            "approved .buildozer incident no longer proves generated-path collision"
        )
    incident_key_migration = next(
        (
            item for item in scan_task_key_rows
            if item["task_id"] == int(task["task_id"])
        ),
        None,
    )
    if incident_key_migration is None:
        raise PipelineError(
            "approved .buildozer incident task key did not migrate"
        )
    contract = {
        "version": 1,
        "kind": "phase8-exact-buildozer-generated-output-filter-extension",
        "directory_segment": ".buildozer",
        "policy": "monotonic-exclusion-certified-result-migration",
        "prior_shared_filter_sha256": prior_shared,
        "current_shared_filter_sha256": current_shared,
        "source_proof_sha256": _sha256(source_proof),
        "completed_scan_tasks_certified": len(result_proofs),
        "completed_result_documents_sha256": _sha256(result_proofs),
        "completed_results_with_buildozer_evidence": 0,
        "certified_checkpoint_scan_result_count": (
            certified_checkpoint_rows
        ),
        "certified_checkpoint_repository_count": len(
            certified_checkpoint_repositories
        ),
        "certified_checkpoint_certificate_sha256": (
            certified_checkpoint_sha256
        ),
        "migrated_scan_result_count": len(migration_rows),
        "migrated_repository_count": len(migrated_repositories),
        "migrated_scan_results_sha256": _sha256(migration_proofs),
        "migrated_scan_task_key_count": len(scan_task_key_rows),
        "migrated_scan_task_keys_sha256": _sha256(scan_task_key_rows),
        "target_detector_fingerprints_sha256": _sha256(
            current_detectors
        ),
        "incident_task_id": int(task["task_id"]),
        "incident_prior_task_key": str(task["task_key"]),
        "incident_task_key": incident_key_migration["target_task_key"],
        "incident_repository_id": str(task["node_id"]),
        "incident_full_name": str(task["full_name"]),
        "incident_head_sha": str(task["head_sha"]),
        "incident_prior_attempts": int(task["attempts"]),
        "tracked_buildozer_path_count": len(buildozer_paths),
        "tracked_buildozer_paths_sha256": _sha256(list(buildozer_paths)),
        "case_collision_count": len(collisions),
        "case_collisions_sha256": _sha256(list(collisions)),
    }
    contract["contract_sha256"] = _sha256(contract)
    return (
        contract,
        tuple(migration_rows),
        tuple(scan_task_key_rows),
    )


def _wall_extension_source_audit(
    root: Path,
    predecessor_source_ref: str,
    expected_predecessor_network_sha256: str,
) -> dict[str, Any]:
    """Prove the wall-only control left network task execution exact."""
    if not predecessor_source_ref or predecessor_source_ref.startswith("-"):
        raise PipelineError("wall extension predecessor source ref is invalid")
    dirty = str(
        _git(root, "status", "--porcelain")
    ).strip()
    if dirty:
        raise PipelineError("wall extension requires a clean tracked worktree")
    predecessor_commit = str(
        _git(
            root,
            "rev-parse",
            "--verify",
            predecessor_source_ref + "^{commit}",
        )
    ).strip()
    successor_commit = str(
        _git(root, "rev-parse", "--verify", "HEAD^{commit}")
    ).strip()
    ancestor = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            predecessor_commit,
            successor_commit,
        ],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if ancestor.returncode != 0:
        raise PipelineError(
            "wall extension predecessor is not an ancestor of current HEAD"
        )
    changed_paths = tuple(
        sorted(
            line
            for line in str(
                _git(
                    root,
                    "diff",
                    "--name-only",
                    predecessor_commit + ".." + successor_commit,
                )
            ).splitlines()
            if line
        )
    )
    unexpected = sorted(
        set(changed_paths) - _WALL_EXTENSION_ALLOWED_PATHS
    )
    if unexpected:
        raise PipelineError(
            "wall extension changed an unapproved path: "
            + ",".join(unexpected)
        )
    initial_required = {
        "collector/cli.py",
        "collector/phase8_control.py",
        "collector/phase8_issue_lane.py",
        "collector/pipeline.py",
        "collector/state.py",
        "test_req14_pipeline.py",
        "test_req14_successor.py",
    }
    recovery_required = {
        "collector/phase8_control.py",
        "collector/pipeline.py",
        "collector/state.py",
        "test_req14_historical_scan_usage.py",
        "test_req14_scan_attempts.py",
        "test_req14_successor.py",
    }
    changed = set(changed_paths)
    if not (
        initial_required <= changed
        or recovery_required <= changed
    ):
        raise PipelineError("wall extension source audit is incomplete")

    predecessor_payloads = {
        path: bytes(
            _git(
                root,
                "show",
                predecessor_commit + ":" + path,
                text=False,
            )
        )
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    predecessor_network_sha256 = _source_payload_sha256(
        predecessor_payloads,
        _CURRENT_NETWORK_TASK_PATHS,
    )
    if predecessor_network_sha256 != expected_predecessor_network_sha256:
        raise PipelineError(
            "wall extension predecessor does not reproduce the recorded "
            "network executable"
        )
    current_payloads = {
        path: (root / path).read_bytes()
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    exact_network = _assert_exact_network_task_semantics(
        predecessor_payloads["collector/pipeline.py"],
        current_payloads["collector/pipeline.py"],
    )
    changed_network_paths = sorted(
        path
        for path in _CURRENT_NETWORK_TASK_PATHS
        if predecessor_payloads[path] != current_payloads[path]
    )
    if changed_network_paths != ["collector/pipeline.py"]:
        raise PipelineError(
            "wall extension changed an unexpected network source path"
        )
    buildozer_source_proof = _approved_buildozer_source_change(
        root, predecessor_commit
    )
    if ("collector/config.py" in changed_paths) != (
        buildozer_source_proof is not None
    ):
        raise PipelineError("approved filter source audit is inconsistent")
    audit = {
        "version": 1,
        "kind": "phase8-owner-wall-extension",
        "predecessor_source_commit": predecessor_commit,
        "successor_source_commit": successor_commit,
        "predecessor_network_task_source_sha256": (
            predecessor_network_sha256
        ),
        "successor_network_task_source_sha256": (
            _network_task_source_sha256()
        ),
        "changed_paths": list(changed_paths),
        "changed_network_paths": changed_network_paths,
        **exact_network,
        "scanner_semantics_changed": buildozer_source_proof is not None,
        "evidence_semantics_changed": buildozer_source_proof is not None,
        "approved_filter_source_proof": buildozer_source_proof,
    }
    audit["source_audit_sha256"] = _sha256(audit)
    return audit


def authorize_phase8_wall_extension(
    *,
    state: StateDB,
    repo_root: Path,
    run_id: str,
    predecessor_source_ref: str,
    extended_limit_seconds: int,
    reason: str,
    cache_root: Path | None = None,
) -> dict[str, Any]:
    """Durably extend the wall and, if present, its exact approved filter fix."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason or ""):
        raise PipelineError("wall extension reason must be machine-readable")
    if (
        not isinstance(extended_limit_seconds, int)
        or isinstance(extended_limit_seconds, bool)
        or not (
            36 * 3600
            < extended_limit_seconds
            <= PHASE8_MAX_OWNER_WALL_SECONDS
        )
    ):
        raise PipelineError("wall extension must be over 36 hours and at most 7 days")
    row = state.connection.execute(
        """
        SELECT mode, plan_json, budgets_json, fingerprints_json, status,
               started_at
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        raise PipelineError("wall extension run does not exist")
    if row["mode"] != "reconcile" or row["status"] not in {"running", "failed"}:
        raise PipelineError("wall extension requires a resumable reconcile run")
    try:
        plan = json.loads(row["plan_json"] or "{}")
        budgets = json.loads(row["budgets_json"] or "{}")
        fingerprints = json.loads(row["fingerprints_json"] or "{}")
        contract = dict(plan["execution_contract"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("wall extension run contract is malformed") from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("release_label") != "Phase 8 Cohort A"
    ):
        raise PipelineError("wall extension is limited to Phase 8 Cohort A")

    baseline = RunBudgets.reconcile().to_dict()
    current_limit = budgets.get("max_wall_seconds")
    existing_extension = contract.get("wall_extension")
    unchanged = dict(budgets)
    unchanged.pop("max_wall_seconds", None)
    baseline_unchanged = dict(baseline)
    baseline_unchanged.pop("max_wall_seconds")
    if unchanged != baseline_unchanged:
        raise PipelineError("wall extension found another changed hard budget")
    if (
        not isinstance(current_limit, int)
        or isinstance(current_limit, bool)
        or current_limit < baseline["max_wall_seconds"]
        or extended_limit_seconds < current_limit
        or (
            extended_limit_seconds == current_limit
            and not isinstance(existing_extension, Mapping)
        )
    ):
        raise PipelineError(
            "wall extension must increase the limit or migrate an already "
            "extended run without changing its ceiling"
        )

    current_fingerprint_document = current_fingerprints().as_dict()
    source_audit = _wall_extension_source_audit(
        repo_root,
        predecessor_source_ref,
        str(contract.get("network_task_source_sha256") or ""),
    )
    filter_extension = None
    filter_migration_rows: tuple[dict[str, Any], ...] = ()
    filter_task_key_rows: tuple[dict[str, Any], ...] = ()
    if fingerprints != current_fingerprint_document:
        source_proof = source_audit.get("approved_filter_source_proof")
        if not isinstance(source_proof, Mapping):
            raise PipelineError(
                "wall extension refuses changed detector or publication fingerprints"
            )
        (
            filter_extension,
            filter_migration_rows,
            filter_task_key_rows,
        ) = (
            _certify_buildozer_filter_extension(
                state=state,
                run_id=run_id,
                prior_fingerprints=fingerprints,
                current_fingerprints_document=current_fingerprint_document,
                source_proof=source_proof,
                cache_root=(
                    cache_root or (repo_root / ".state" / "git-cache")
                ),
            )
        )
    elif source_audit.get("approved_filter_source_proof") is not None:
        raise PipelineError(
            "approved filter source changed without a fingerprint migration"
        )
    unchanged_sha256 = _sha256(unchanged)
    authorized_at = (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    try:
        authorized_dt = datetime.datetime.fromisoformat(
            authorized_at.replace("Z", "+00:00")
        )
        started_dt = datetime.datetime.fromisoformat(
            str(row["started_at"]).replace("Z", "+00:00")
        )
    except (TypeError, ValueError) as exc:
        raise PipelineError("wall extension run start time is invalid") from exc
    pre_extension_elapsed = max(
        0.0, (authorized_dt - started_dt).total_seconds()
    )
    prior_historical_wall = float(
        contract.get("historical_wall_seconds", 0) or 0
    )
    charged_wall = prior_historical_wall + pre_extension_elapsed
    if charged_wall >= extended_limit_seconds:
        raise PipelineError("wall extension leaves no remaining run time")
    extension = {
        "version": 1,
        "original_limit_seconds": baseline["max_wall_seconds"],
        "extended_limit_seconds": extended_limit_seconds,
        "reason": reason,
        "authorized_at": authorized_at,
        "predecessor_source_commit": source_audit[
            "predecessor_source_commit"
        ],
        "successor_source_commit": source_audit[
            "successor_source_commit"
        ],
        "source_audit_sha256": source_audit["source_audit_sha256"],
        "unchanged_budgets_sha256": unchanged_sha256,
        "prior_historical_wall_seconds": prior_historical_wall,
        "pre_extension_run_elapsed_seconds": pre_extension_elapsed,
        "charged_wall_seconds": charged_wall,
    }
    updated_plan = copy.deepcopy(plan)
    updated_contract = dict(contract)
    updated_contract.update({
        "network_task_source_sha256": source_audit[
            "successor_network_task_source_sha256"
        ],
        "wall_extension": extension,
        "reviewed_slo": {
            "class": "partial_cohort_reconciliation",
            "target_seconds": 24 * 3600,
            "ceiling_seconds": extended_limit_seconds,
        },
        "historical_wall_seconds": charged_wall,
    })
    if filter_extension is not None:
        updated_contract["filter_extension"] = filter_extension
    updated_plan["execution_contract"] = updated_contract
    if filter_extension is not None:
        updated_plan["fingerprints"] = current_fingerprint_document
    updated_budgets = dict(budgets)
    updated_budgets["max_wall_seconds"] = extended_limit_seconds
    checkpoint = {
        "extension": extension,
        "source_audit": source_audit,
        "completed_scan_tasks_preserved": int(
            state.connection.execute(
                """
                SELECT COUNT(*) FROM tasks
                WHERE run_id=? AND stage='scan' AND status='complete'
                """,
                (run_id,),
            ).fetchone()[0]
        ),
        "reset_scan_tasks": 0,
        "other_budget_changes": 0,
        "filter_extension": filter_extension,
    }
    with state.transaction(immediate=True):
        for migrated_task in filter_task_key_rows:
            changed = state.connection.execute(
                """
                UPDATE tasks SET task_key=?,updated_at=?
                WHERE task_id=? AND task_key=?
                """,
                (
                    migrated_task["target_task_key"],
                    authorized_at,
                    migrated_task["task_id"],
                    migrated_task["prior_task_key"],
                ),
            ).rowcount
            if changed != 1:
                raise PipelineError(
                    "approved scan task key migration changed concurrently"
                )
        for migrated in filter_migration_rows:
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
        state.connection.execute(
            """
            UPDATE runs SET plan_json=?, budgets_json=?, fingerprints_json=?,
                checkpoint_at=?, started_at=?
            WHERE run_id=?
            """,
            (
                canonical_json(updated_plan),
                canonical_json(updated_budgets),
                canonical_json(current_fingerprint_document),
                authorized_at,
                authorized_at,
                run_id,
            ),
        )
        state.update_stage(
            run_id,
            "wall_extension",
            status="complete",
            counters={
                "original_limit_seconds": baseline["max_wall_seconds"],
                "extended_limit_seconds": extended_limit_seconds,
                "completed_scan_tasks_preserved": checkpoint[
                    "completed_scan_tasks_preserved"
                ],
            },
            metrics={
                "other_budget_changes": 0,
                "reset_scan_tasks": 0,
                "filter_extension_applied": int(filter_extension is not None),
            },
            checkpoint=checkpoint,
        )
    return {
        "run_id": run_id,
        "status": row["status"],
        "wall_extension": extension,
        "completed_scan_tasks_preserved": checkpoint[
            "completed_scan_tasks_preserved"
        ],
        "other_budget_changes": 0,
        "reset_scan_tasks": 0,
        "filter_extension": filter_extension,
        "launchd_armed": False,
    }


def authorize_phase8_issue_retry(
    *,
    state: StateDB,
    run_id: str,
    reason: str,
) -> dict[str, Any]:
    """Requeue only fully-accounted transient Phase 8 scan incidents."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason or ""):
        raise PipelineError("issue retry reason must be machine-readable")
    run = state.connection.execute(
        """
        SELECT mode, plan_json, budgets_json, fingerprints_json, status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None:
        raise PipelineError("issue retry run does not exist")
    if run["mode"] != "reconcile" or run["status"] not in {
        "running", "failed"
    }:
        raise PipelineError("issue retry requires a resumable reconcile run")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        contract = dict(plan["execution_contract"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("issue retry run contract is malformed") from exc
    if (
        contract.get("run_class") != "phase8-cohort-a"
        or contract.get("release_scope") != "partial-portfolio"
        or contract.get("network_task_source_sha256")
        != _network_task_source_sha256()
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError("issue retry execution contract is incompatible")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall <= actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("issue retry found a changed safety budget")

    rows = state.connection.execute(
        """
        SELECT t.task_id, t.task_key, t.repository_id, t.attempts,
               t.max_attempts, t.error_code AS task_error_code,
               sa.status AS attempt_status, sa.retryable,
               sa.error_code, sa.error_detail, sa.usage_complete
        FROM tasks t
        JOIN scan_attempts sa
          ON sa.task_id=CAST(t.task_id AS TEXT)
         AND sa.attempt=t.attempts
        WHERE t.run_id=? AND t.stage='scan' AND t.status='failed'
        ORDER BY t.task_id
        """,
        (run_id,),
    ).fetchall()
    selected = []
    for row in rows:
        detail = " ".join(str(row["error_detail"] or "").split())
        normalized_code, normalized_retryable, _normalized_detail = (
            _phase8_runtime_issue_contract(
                str(row["error_code"]),
                bool(row["retryable"]),
                detail,
            )
        )
        exact_runtime_reclassification = (
            normalized_code != row["error_code"]
            and normalized_retryable
        )
        eligible_transient = (
            normalized_code in _TRANSIENT_SCAN_ISSUES
            and normalized_retryable
        )
        if not eligible_transient:
            continue
        if (
            row["attempt_status"] != "failed"
            or int(row["usage_complete"] or 0) != 1
            or int(row["attempts"]) <= 0
        ):
            raise PipelineError(
                "issue retry refuses incomplete attempt accounting"
            )
        selected.append({
            "task_id": int(row["task_id"]),
            "task_key": str(row["task_key"]),
            "repository_id": str(row["repository_id"]),
            "attempts": int(row["attempts"]),
            "max_attempts": int(row["max_attempts"]),
            "prior_error_code": str(row["error_code"]),
            "normalized_error_code": normalized_code,
            "policy": (
                "exact_runtime_reclassification"
                if exact_runtime_reclassification
                else "bounded_transient_retry"
            ),
        })
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
    completed_before = int(state.connection.execute(
        """
        SELECT COUNT(*) FROM tasks
        WHERE run_id=? AND stage='scan' AND status='complete'
        """,
        (run_id,),
    ).fetchone()[0])
    with state.transaction(immediate=True):
        for item in selected:
            changed = state.connection.execute(
                """
                UPDATE tasks SET status='pending',
                    max_attempts=CASE
                        WHEN max_attempts <= attempts THEN attempts + 1
                        ELSE max_attempts
                    END,
                    lease_owner=NULL, lease_expires_at=NULL,
                    available_at=0, error_code=?, updated_at=?,
                    finished_at=NULL
                WHERE task_id=? AND status='failed'
                  AND attempts=? AND task_key=?
                """,
                (
                    "issue_retry:" + item["policy"],
                    now,
                    item["task_id"],
                    item["attempts"],
                    item["task_key"],
                ),
            ).rowcount
            if changed != 1:
                raise PipelineError("issue retry task changed during control")
        checkpoint = {
            "version": 1,
            "reason": reason,
            "authorized_at": now,
            "selection_sha256": selection_sha256,
            "selected_tasks": selected,
            "reset_task_count": len(selected),
            "completed_scan_tasks_preserved": completed_before,
            "other_budget_changes": 0,
        }
        state.update_stage(
            run_id,
            "phase8_issue_retry",
            status="complete",
            counters={
                "reset_task_count": len(selected),
                "completed_scan_tasks_preserved": completed_before,
            },
            metrics={"other_budget_changes": 0},
            checkpoint=checkpoint,
        )
    return {
        "run_id": run_id,
        "status": run["status"],
        "reset_task_count": len(selected),
        "selection_sha256": selection_sha256,
        "completed_scan_tasks_preserved": completed_before,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }


def authorize_phase8_buildozer_retry(
    *,
    state: StateDB,
    run_id: str,
    reason: str,
) -> dict[str, Any]:
    """Requeue only the certified shootAnalyzer generated-tree incident."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason or ""):
        raise PipelineError("buildozer retry reason must be machine-readable")
    run = state.connection.execute(
        """
        SELECT mode,plan_json,budgets_json,fingerprints_json,status
        FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["mode"] != "reconcile" or run["status"] not in {
        "running", "failed"
    }:
        raise PipelineError("buildozer retry requires a resumable reconcile run")
    try:
        plan = json.loads(run["plan_json"] or "{}")
        execution = dict(plan["execution_contract"])
        proof = dict(execution["filter_extension"])
        proof_sha256 = proof.pop("contract_sha256")
        fingerprints = json.loads(run["fingerprints_json"] or "{}")
        budgets = RunBudgets(**json.loads(run["budgets_json"] or "{}"))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("buildozer retry contract is malformed") from exc
    if (
        execution.get("run_class") != "phase8-cohort-a"
        or execution.get("release_scope") != "partial-portfolio"
        or execution.get("network_task_source_sha256")
        != _network_task_source_sha256()
        or fingerprints != current_fingerprints().as_dict()
        or proof.get("version") != 1
        or proof.get("kind")
        != "phase8-exact-buildozer-generated-output-filter-extension"
        or proof.get("directory_segment") != ".buildozer"
        or proof.get("policy")
        != "monotonic-exclusion-certified-result-migration"
        or proof.get("completed_results_with_buildozer_evidence") != 0
        or proof.get("incident_full_name") != _BUILDOZER_REPOSITORY
        or _sha256(proof) != proof_sha256
    ):
        raise PipelineError("buildozer retry execution contract is incompatible")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    actual_wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall <= actual_wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("buildozer retry found a changed safety budget")

    task = state.connection.execute(
        """
        SELECT t.task_id,t.task_key,t.status,t.attempts,t.max_attempts,
               t.error_code,r.node_id,r.full_name,r.head_sha,
               sa.status AS attempt_status,sa.error_code AS attempt_error_code,
               sa.usage_complete
        FROM tasks t JOIN repositories r ON r.node_id=t.repository_id
        JOIN scan_attempts sa
          ON sa.task_id=CAST(t.task_id AS TEXT) AND sa.attempt=t.attempts
        WHERE t.run_id=? AND t.stage='scan' AND t.task_id=?
        """,
        (run_id, int(proof["incident_task_id"])),
    ).fetchone()
    if (
        task is None
        or int(task["task_id"]) != int(proof["incident_task_id"])
        or task["task_key"] != proof["incident_task_key"]
        or task["node_id"] != proof["incident_repository_id"]
        or task["full_name"] != proof["incident_full_name"]
        or task["head_sha"] != proof["incident_head_sha"]
        or int(task["attempts"]) != int(proof["incident_prior_attempts"])
        or task["status"] != "failed"
        or task["error_code"] != "detector_error"
        or task["attempt_status"] != "failed"
        or task["attempt_error_code"] != "detector_error"
        or int(task["usage_complete"] or 0) != 1
    ):
        raise PipelineError("buildozer retry incident changed after certification")
    usage = _scan_attempt_usage_for_run(state, run_id)
    _enforce_scan_attempt_budgets(usage, planned_attempts=1, budgets=budgets)
    now = (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    completed_before = int(state.connection.execute(
        """
        SELECT COUNT(*) FROM tasks
        WHERE run_id=? AND stage='scan' AND status='complete'
        """,
        (run_id,),
    ).fetchone()[0])
    checkpoint = {
        "version": 1,
        "reason": reason,
        "authorized_at": now,
        "filter_extension_contract_sha256": proof_sha256,
        "task_id": int(task["task_id"]),
        "task_key": str(task["task_key"]),
        "repository": str(task["full_name"]),
        "prior_attempts": int(task["attempts"]),
        "completed_scan_tasks_preserved": completed_before,
        "reset_task_count": 1,
        "other_budget_changes": 0,
    }
    with state.transaction(immediate=True):
        changed = state.connection.execute(
            """
            UPDATE tasks SET status='pending',
                max_attempts=CASE
                    WHEN max_attempts <= attempts THEN attempts + 1
                    ELSE max_attempts
                END,
                lease_owner=NULL,lease_expires_at=NULL,available_at=0,
                error_code='issue_retry:approved_buildozer_exclusion',
                updated_at=?,finished_at=NULL
            WHERE task_id=? AND status='failed' AND attempts=? AND task_key=?
            """,
            (
                now,
                int(task["task_id"]),
                int(task["attempts"]),
                str(task["task_key"]),
            ),
        ).rowcount
        if changed != 1:
            raise PipelineError("buildozer retry task changed during control")
        state.update_stage(
            run_id,
            "phase8_buildozer_issue_retry",
            status="complete",
            counters={
                "reset_task_count": 1,
                "completed_scan_tasks_preserved": completed_before,
            },
            metrics={"other_budget_changes": 0},
            checkpoint=checkpoint,
        )
    return {
        "run_id": run_id,
        "status": run["status"],
        "reset_task_count": 1,
        "task_id": int(task["task_id"]),
        "repository": str(task["full_name"]),
        "completed_scan_tasks_preserved": completed_before,
        "other_budget_changes": 0,
        "launchd_armed": False,
    }
