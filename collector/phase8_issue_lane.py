"""Audited Phase 8 repository-issue recovery without checkpoint replay.

This is not a general detector bypass.  It derives the exact set of public
notebook blobs that failed strict JSON parsing, re-proves that their
serialized authored surface cannot contain any configured CUDA-X retention
token, and then gives only those exact bytes the existing fast-negative
notebook treatment.  Every other blob remains fail-closed.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from . import config, triage
from .evidence_content import parse_lfs_pointer
from .fingerprints import canonical_json
from .github_client import RepositoryMetadata
from .pipeline import (
    PHASE8_MAX_OWNER_WALL_SECONDS,
    CollectorPipeline,
    PipelineError,
    RunBudgets,
    _enforce_scan_attempt_budgets,
    _network_task_source_sha256,
    _scan_attempt_usage_for_run,
)
from .planner import build_plan, current_fingerprints
from .scanner_v2 import _worker
from .state import StateDB


_RETENTION_TOKEN_SHA256 = (
    "ad57bfad663847d0a31ef36bd562cad8e30752f1ba83db9d78b5aa6cd55c79e4"
)
_MAX_CERTIFIED_ATTEMPTS = 3
_GIB = 1024**3
_TOLERANT_JSON_STRING = re.compile(r'"(?:\\[\s\S]|[^"\\])*"')
_BLOCKED_LFS_INSPECTION_RE = re.compile(
    r"\Acould not inspect detector-relevant LFS path: "
    r"(?P<path>.+) \(errno=1\)\Z"
)


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _retention_tokens() -> tuple[str, ...]:
    return tuple(sorted({
        token.casefold()
        for library in triage.ALL_LIBRARIES
        for token in triage._broad_tokens(library)
        if token
    }))


def _encoded_token_pattern(tokens: Iterable[str]) -> re.Pattern[str]:
    pattern = triage._notebook_retention_pattern(tokens)
    if pattern is None:
        raise PipelineError("notebook proof retention-token universe is empty")
    return pattern


def _repo_cache_path(cache_root: Path, full_name: str) -> Path:
    key = hashlib.sha256(full_name.casefold().encode("utf-8")).hexdigest()
    return cache_root / "repos" / (key + ".git")


def _git_blob(
    git_dir: Path,
    head_sha: str,
    path: str,
) -> tuple[str, bytes]:
    env = os.environ.copy()
    env["GIT_NO_LAZY_FETCH"] = "1"
    tree = subprocess.run(
        [
            "git", "--git-dir", str(git_dir), "-c", "core.quotePath=false",
            "ls-tree", "-z", head_sha, "--", path,
        ],
        capture_output=True,
        check=False,
        env=env,
        timeout=60,
    )
    if tree.returncode or not tree.stdout.endswith(b"\0"):
        raise PipelineError("certified notebook tree entry is unavailable")
    metadata, separator, encoded_path = tree.stdout[:-1].partition(b"\t")
    fields = metadata.split()
    decoded_path = encoded_path.decode("utf-8", errors="surrogateescape")
    if (
        not separator
        or len(fields) != 3
        or fields[1] != b"blob"
        or decoded_path != path
    ):
        raise PipelineError("certified notebook tree identity changed")
    object_id = fields[2].decode("ascii", errors="strict")
    blob = subprocess.run(
        ["git", "--git-dir", str(git_dir), "cat-file", "blob", object_id],
        capture_output=True,
        check=False,
        env=env,
        timeout=180,
    )
    if blob.returncode:
        raise PipelineError("certified notebook blob is unavailable locally")
    return object_id, blob.stdout


def _git_attributes(
    git_dir: Path,
    head_sha: str,
    path: str,
) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ATTR_SOURCE": str(head_sha),
    })
    result = subprocess.run(
        [
            "git", "--git-dir", str(git_dir), "check-attr",
            "--source", str(head_sha), "-z",
            "filter", "working-tree-encoding", "ident", "text", "eol",
            "--", path,
        ],
        capture_output=True,
        check=False,
        env=environment,
        timeout=60,
    )
    fields = result.stdout.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if result.returncode or len(fields) != 15:
        raise PipelineError("blocked LFS-path attributes are unavailable")
    attributes = {}
    for offset in range(0, len(fields), 3):
        decoded_path = fields[offset].decode(
            "utf-8", errors="surrogateescape"
        )
        if decoded_path != path:
            raise PipelineError("blocked LFS-path attribute identity changed")
        attributes[fields[offset + 1].decode("ascii")] = fields[
            offset + 2
        ].decode("utf-8", errors="replace")
    return attributes


def _verify_negative_blob(raw: bytes, pattern: re.Pattern[str]) -> dict[str, Any]:
    rendered = raw.decode("utf-8", errors="replace")
    surface_policy = "parsed_authored_cells_only"
    try:
        surfaces = triage.parse_notebook_surfaces(rendered)
    except triage.NotebookEvidenceError:
        surfaces = None
    if surfaces is None:
        # The 104 MB incident has one invalid non-ASCII byte between JSON
        # tokens. Removing every invalid UTF-8 byte is conservative for this
        # proof: if a byte interrupted a detector literal, removal recreates
        # the literal and the universal token search below rejects it.
        ignored = raw.decode("utf-8", errors="ignore")
        if ignored != rendered:
            try:
                surfaces = triage.parse_notebook_surfaces(ignored)
                surface_policy = (
                    "invalid_utf8_removed_then_authored_cells_only"
                )
            except triage.NotebookEvidenceError:
                surfaces = None
    if surfaces is not None:
        authored = surfaces.search_text.casefold()
        match = pattern.search(authored)
        if match is not None:
            raise PipelineError(
                "certified malformed notebook contains a retention token"
            )
        encoded = authored.encode("utf-8", errors="replace")
        return {
            "masked_text_sha256": hashlib.sha256(encoded).hexdigest(),
            "masked_text_bytes": len(encoded),
            "retention_token_hits": [],
            "base64_mask_policy": surface_policy,
            "json_escape_aware": True,
        }

    tolerant = _tolerant_notebook_source_text(
        raw.decode("utf-8", errors="ignore")
    )
    if tolerant is not None:
        authored, cell_count, source_count = tolerant
        authored = authored.casefold()
        match = pattern.search(authored)
        if match is not None:
            raise PipelineError(
                "certified malformed notebook contains a retention token"
            )
        encoded = authored.encode("utf-8", errors="replace")
        return {
            "masked_text_sha256": hashlib.sha256(encoded).hexdigest(),
            "masked_text_bytes": len(encoded),
            "retention_token_hits": [],
            "base64_mask_policy": "tolerant_complete_source_arrays_only",
            "json_escape_aware": True,
            "cell_count": cell_count,
            "source_count": source_count,
        }

    masked = triage._NOTEBOOK_BASE64_RUN.sub("", rendered.casefold())
    # Decode the two JSON escape forms that can conceal a configured literal.
    # This intentionally over-approximates malformed strings: a doubled escape
    # may become searchable even when a strict parser would leave it literal.
    escape_decoded = re.sub(
        r"\\u([0-9a-f]{4})",
        lambda match: chr(int(match.group(1), 16)),
        masked,
        flags=re.IGNORECASE,
    ).replace(r"\/", "/")
    match = pattern.search(escape_decoded)
    if match is not None:
        raise PipelineError(
            "certified malformed notebook contains a retention token"
        )
    return {
        "masked_text_sha256": hashlib.sha256(
            escape_decoded.encode("utf-8", errors="replace")
        ).hexdigest(),
        "masked_text_bytes": len(
            escape_decoded.encode("utf-8", errors="replace")
        ),
        "retention_token_hits": [],
        "base64_mask_policy": "triage._NOTEBOOK_BASE64_RUN",
        "json_escape_aware": True,
    }


def _tolerant_notebook_source_text(
    rendered: str,
) -> tuple[str, int, int] | None:
    """Extract every cell source while treating invalid output escapes as data."""
    stack = []
    cell_count = 0
    sources = []
    previous = 0

    def structural(segment: str) -> bool:
        for character in segment:
            if character in "[{":
                stack.append(character)
            elif character == "]":
                if not stack or stack.pop() != "[":
                    return False
            elif character == "}":
                if not stack or stack.pop() != "{":
                    return False
        return True

    def key_end(match: re.Match[str], key: str) -> int | None:
        if match.group(0) != json.dumps(key):
            return None
        cursor = match.end()
        while cursor < len(rendered) and rendered[cursor].isspace():
            cursor += 1
        if cursor >= len(rendered) or rendered[cursor] != ":":
            return None
        cursor += 1
        while cursor < len(rendered) and rendered[cursor].isspace():
            cursor += 1
        return cursor

    def source_value(cursor: int) -> str | None:
        if cursor >= len(rendered):
            return None
        if rendered[cursor] == '"':
            match = _TOLERANT_JSON_STRING.match(rendered, cursor)
            if match is None:
                return None
            try:
                value = json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, str) else None
        if rendered[cursor] != "[":
            return None
        cursor += 1
        values = []
        while True:
            while cursor < len(rendered) and rendered[cursor].isspace():
                cursor += 1
            if cursor < len(rendered) and rendered[cursor] == "]":
                return "".join(values)
            match = _TOLERANT_JSON_STRING.match(rendered, cursor)
            if match is None:
                return None
            try:
                value = json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
            if not isinstance(value, str):
                return None
            values.append(value)
            cursor = match.end()
            while cursor < len(rendered) and rendered[cursor].isspace():
                cursor += 1
            if cursor < len(rendered) and rendered[cursor] == ",":
                cursor += 1
                continue
            if cursor < len(rendered) and rendered[cursor] == "]":
                return "".join(values)
            return None

    for match in _TOLERANT_JSON_STRING.finditer(rendered):
        if not structural(rendered[previous:match.start()]):
            return None
        previous = match.end()
        if key_end(match, "cell_type") is not None:
            cell_count += 1
        cursor = key_end(match, "source")
        if cursor is not None:
            value = source_value(cursor)
            if value is None:
                return None
            sources.append(value)
    if not structural(rendered[previous:]) or stack:
        return None
    if cell_count <= 0 or len(sources) != cell_count:
        return None
    return "\n".join(sources), cell_count, len(sources)


def verify_notebook_negative_contract(
    *,
    state: StateDB,
    cache_root: Path,
    run_id: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Re-prove public identity, exact bytes, and universal token absence."""
    tokens = _retention_tokens()
    token_sha256 = _sha256(list(tokens))
    if token_sha256 != _RETENTION_TOKEN_SHA256:
        raise PipelineError("notebook proof retention-token universe changed")
    pattern = _encoded_token_pattern(tokens)
    proofs = []
    blobs = {}
    incident_rows = state.connection.execute(
        """
        SELECT t.task_id, t.task_key, t.payload_json, t.status, t.attempts,
               r.node_id, r.full_name, r.visibility, r.is_fork,
               r.is_archived, r.head_sha, sa.attempt, sa.error_detail
        FROM tasks t
        JOIN repositories r ON r.node_id=t.repository_id
        JOIN scan_attempts sa ON sa.task_id=CAST(t.task_id AS TEXT)
        WHERE t.run_id=? AND t.stage='scan'
          AND sa.error_code='invalid_notebook'
          AND sa.status='failed' AND sa.usage_complete=1
        ORDER BY t.task_id, sa.attempt
        """,
        (run_id,),
    ).fetchall()
    seen = set()
    for incident in incident_rows:
        detail = str(incident["error_detail"] or "")
        prefix = "tracked notebook is invalid JSON; scan is incomplete: "
        if not detail.startswith(prefix):
            raise PipelineError("notebook proof failure path is malformed")
        path = detail[len(prefix):]
        identity = (int(incident["task_id"]), path)
        if identity in seen:
            continue
        seen.add(identity)
        payload = json.loads(incident["payload_json"] or "{}")
        expected = {
            "repository_id": str(incident["node_id"]),
            "full_name": str(incident["full_name"]),
            "head_sha": str(incident["head_sha"]),
            "path": path,
            "candidate_library_ids": tuple(payload.get("libraries") or ()),
            "reason": "exact_malformed_notebook_token_negative",
        }
        repository = state.connection.execute(
            """
            SELECT node_id, full_name, visibility, is_fork, is_archived,
                   head_sha FROM repositories WHERE node_id=?
            """,
            (expected["repository_id"],),
        ).fetchone()
        if (
            repository is None
            or repository["full_name"] != expected["full_name"]
            or repository["visibility"] != "public"
            or int(repository["is_fork"]) != 0
            or int(repository["is_archived"]) != 0
            or repository["head_sha"] != expected["head_sha"]
        ):
            raise PipelineError("notebook proof public repository changed")
        task = incident
        if (
            payload.get("full_name") != expected["full_name"]
            or payload.get("head_sha") != expected["head_sha"]
            or tuple(payload.get("libraries") or ())
            != expected["candidate_library_ids"]
            or task["status"] not in {"pending", "failed", "complete"}
            or int(task["attempts"]) < 1
        ):
            raise PipelineError("notebook proof scan task identity changed")
        object_id, raw = _git_blob(
            _repo_cache_path(cache_root, expected["full_name"]),
            expected["head_sha"],
            expected["path"],
        )
        raw_sha256 = hashlib.sha256(raw).hexdigest()
        negative = _verify_negative_blob(raw, pattern)
        blobs[raw_sha256] = raw
        proofs.append({
            **expected,
            "blob_oid": object_id,
            "blob_bytes": len(raw),
            "blob_sha256": raw_sha256,
            "candidate_library_ids": list(
                expected["candidate_library_ids"]
            ),
            "task_id": int(task["task_id"]),
            "task_key": str(task["task_key"]),
            "prior_invalid_attempts_certified_minimum": 1,
            **negative,
        })
    if not proofs:
        raise PipelineError("notebook proof found no accounted incidents")
    contract = {
        "version": 1,
        "kind": "phase8-exact-malformed-notebook-negative-proof",
        "run_id": run_id,
        "retention_token_count": len(tokens),
        "retention_token_sha256": token_sha256,
        "proofs": proofs,
    }
    contract["contract_sha256"] = _sha256(contract)
    return contract, blobs


def verify_blocked_lfs_inspection_contract(
    *,
    state: StateDB,
    cache_root: Path,
    run_id: str,
) -> tuple[dict[str, Any], dict[tuple[str, str], bytes]]:
    """Prove exact public Git blobs behind macOS-denied worktree reads."""
    incidents = state.connection.execute(
        """
        SELECT t.task_id, t.task_key, t.payload_json, t.status, t.attempts,
               r.node_id, r.full_name, r.visibility, r.is_fork,
               r.is_archived, r.head_sha, sa.attempt, sa.error_detail
        FROM tasks t
        JOIN repositories r ON r.node_id=t.repository_id
        JOIN scan_attempts sa ON sa.task_id=CAST(t.task_id AS TEXT)
        WHERE t.run_id=? AND t.stage='scan'
          AND sa.status='failed' AND sa.usage_complete=1
          AND sa.error_detail LIKE
              'could not inspect detector-relevant LFS path:%(errno=1)'
        ORDER BY t.task_id, sa.attempt
        """,
        (run_id,),
    ).fetchall()
    proofs = []
    blobs: dict[tuple[str, str], bytes] = {}
    seen = set()
    for incident in incidents:
        detail = " ".join(str(incident["error_detail"] or "").split())
        matched = _BLOCKED_LFS_INSPECTION_RE.fullmatch(detail)
        if matched is None:
            raise PipelineError("blocked LFS-path failure is malformed")
        path = matched.group("path")
        identity = (int(incident["task_id"]), path)
        if identity in seen:
            continue
        seen.add(identity)
        payload = json.loads(incident["payload_json"] or "{}")
        expected_libraries = tuple(payload.get("libraries") or ())
        if (
            incident["visibility"] != "public"
            or int(incident["is_fork"]) != 0
            or int(incident["is_archived"]) != 0
            or payload.get("full_name") != incident["full_name"]
            or payload.get("head_sha") != incident["head_sha"]
            or not expected_libraries
            or incident["status"] not in {"pending", "failed", "complete"}
            or int(incident["attempts"]) < 1
        ):
            raise PipelineError("blocked LFS-path task identity changed")
        git_dir = _repo_cache_path(cache_root, incident["full_name"])
        object_id, raw = _git_blob(
            git_dir, incident["head_sha"], path
        )
        if len(raw) > 4096 or parse_lfs_pointer(raw) is not None:
            raise PipelineError(
                "blocked LFS-path proof is not an exact non-pointer"
            )
        attributes = _git_attributes(
            git_dir, incident["head_sha"], path
        )
        if attributes.get("filter") not in {"unspecified", "unset"}:
            raise PipelineError(
                "blocked LFS-path proof found a checkout filter"
            )
        if attributes.get("working-tree-encoding") not in {
            "unspecified", "unset"
        }:
            raise PipelineError(
                "blocked LFS-path proof found a working-tree encoding"
            )
        repo_key = hashlib.sha256(
            str(incident["full_name"]).casefold().encode("utf-8")
        ).hexdigest()
        raw_sha256 = hashlib.sha256(raw).hexdigest()
        blobs[(repo_key[:12], path)] = raw
        proofs.append({
            "task_id": int(incident["task_id"]),
            "task_key": str(incident["task_key"]),
            "repository_id": str(incident["node_id"]),
            "full_name": str(incident["full_name"]),
            "head_sha": str(incident["head_sha"]),
            "path": path,
            "candidate_library_ids": list(expected_libraries),
            "blob_oid": object_id,
            "blob_bytes": len(raw),
            "blob_sha256": raw_sha256,
            "git_attributes": attributes,
            "lfs_pointer": False,
            "read_authority": "exact-local-git-blob",
            "reason": "macos_worktree_read_denied_errno_1",
        })
    if not proofs:
        raise PipelineError("blocked LFS-path proof found no incidents")
    contract = {
        "version": 1,
        "kind": "phase8-exact-blocked-lfs-inspection-proof",
        "run_id": run_id,
        "proofs": proofs,
    }
    contract["contract_sha256"] = _sha256(contract)
    return contract, blobs


@contextlib.contextmanager
def _exact_notebook_negatives(blob_sha256s: Iterable[str]):
    allowed = frozenset(blob_sha256s)
    original = triage._notebook_might_affect_verdict

    def exact_or_original(raw, retention_re):
        encoded = (
            raw
            if isinstance(raw, bytes)
            else str(raw).encode("utf-8", errors="surrogatepass")
        )
        if hashlib.sha256(encoded).hexdigest() in allowed:
            return False
        return original(raw, retention_re)

    triage._notebook_might_affect_verdict = exact_or_original
    try:
        yield
    finally:
        triage._notebook_might_affect_verdict = original


@contextlib.contextmanager
def _exact_blocked_worktree_reads(
    cache_root: Path,
    blobs: dict[tuple[str, str], bytes],
):
    """Substitute an exact Git blob only for a certified denied read."""
    worktrees = (Path(cache_root).resolve() / "worktrees")
    allowed = dict(blobs)
    original = Path.read_bytes

    def exact_or_original(path):
        absolute = Path(os.path.abspath(os.fspath(path)))
        candidates = [absolute]
        try:
            resolved = absolute.resolve(strict=False)
        except OSError:
            resolved = absolute
        if resolved != absolute:
            candidates.append(resolved)
        relative = None
        for candidate in candidates:
            try:
                relative = candidate.relative_to(worktrees)
                break
            except ValueError:
                continue
        if relative is None:
            return original(path)
        if len(relative.parts) < 2:
            return original(path)
        worktree_name = relative.parts[0]
        relpath = "/".join(relative.parts[1:])
        for (prefix, expected_path), raw in allowed.items():
            if (
                worktree_name.startswith(prefix + "-")
                and relpath == expected_path
            ):
                return raw
        return original(path)

    Path.read_bytes = exact_or_original
    try:
        yield
    finally:
        Path.read_bytes = original


def _single_process_runner(
    tasks,
    libraries,
    cache_root,
    *,
    workers,
    repo_timeout,
    cache_target_bytes,
    cache_hard_bytes,
    on_result,
    before_task,
    on_heartbeat,
    run_deadline,
):
    if int(workers) != 1:
        raise PipelineError("certified issue lane must use one worker")
    outcomes = []
    registry_root = Path(cache_root) / "process-groups"
    registry_root.mkdir(parents=True, exist_ok=True)
    for task in tasks:
        before_task(task)
        stop = threading.Event()
        heartbeat_errors = []

        def heartbeat_loop():
            while not stop.wait(60):
                try:
                    on_heartbeat()
                except BaseException as exc:
                    heartbeat_errors.append(exc)
                    stop.set()
                    return

        heartbeat = threading.Thread(
            target=heartbeat_loop,
            name="phase8-notebook-issue-heartbeat",
            daemon=True,
        )
        heartbeat.start()
        registry = registry_root / (
            "%d-%s.active" % (os.getpid(), uuid.uuid4().hex)
        )
        try:
            outcome = _worker((
                task,
                libraries,
                str(Path(cache_root).resolve()),
                int(cache_target_bytes),
                int(cache_hard_bytes),
                int(repo_timeout),
                "https://github.com/{full_name}.git",
                run_deadline,
                str(registry),
                2 * _GIB,
            ))
        finally:
            stop.set()
            heartbeat.join(timeout=65)
            registry.unlink(missing_ok=True)
        if heartbeat_errors:
            raise PipelineError(
                "certified issue task lease heartbeat failed"
            ) from heartbeat_errors[0]
        on_result(outcome)
        outcomes.append(outcome)
    return outcomes


def _metadata(row) -> RepositoryMetadata:
    detail = json.loads(row["metadata_json"] or "{}")
    display = detail.get("display") or {}
    return RepositoryMetadata(
        request_key="node:" + str(row["node_id"]),
        requested_node_id=str(row["node_id"]),
        requested_full_name=str(row["full_name"]),
        node_id=str(row["node_id"]),
        full_name=str(row["full_name"]),
        visibility="PUBLIC",
        is_private=False,
        is_fork=False,
        is_archived=False,
        default_branch=row["default_branch"],
        head_oid=str(row["head_sha"]),
        renamed=False,
        status="ok",
        disk_usage_kb=detail.get("disk_usage_kb"),
        description=display.get("description"),
        stars=int(display.get("stars") or 0),
        forks=int(display.get("forks") or 0),
        language=display.get("language"),
        created_at=display.get("created_at"),
        pushed_at=display.get("pushed_at"),
    )


def _run_certified_issue_lane(
    *,
    state: StateDB,
    repo_root: Path,
    state_path: str,
    cache_root: str,
    data_dir: str,
    run_id: str,
    verifier,
    override,
    retry_label: str,
    stage_name: str,
    counter_name: str,
) -> dict[str, Any]:
    """Run exact certified issue tasks through normal durable checkpoints."""
    run = state.connection.execute(
        """
        SELECT mode, plan_json, budgets_json, fingerprints_json, status,
               started_at FROM runs WHERE run_id=?
        """,
        (run_id,),
    ).fetchone()
    if run is None or run["status"] not in {"running", "failed"}:
        raise PipelineError("certified issue run is not resumable")
    try:
        plan_document = json.loads(run["plan_json"])
        execution = dict(plan_document["execution_contract"])
        budgets = RunBudgets(**json.loads(run["budgets_json"]))
        fingerprints = json.loads(run["fingerprints_json"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError("certified issue run contract is malformed") from exc
    if (
        run["mode"] != "reconcile"
        or execution.get("run_class") != "phase8-cohort-a"
        or execution.get("network_task_source_sha256")
        != _network_task_source_sha256()
        or fingerprints != current_fingerprints().as_dict()
    ):
        raise PipelineError("certified issue run contract is incompatible")
    baseline = RunBudgets.reconcile().to_dict()
    actual = budgets.to_dict()
    wall = actual.pop("max_wall_seconds")
    baseline_wall = baseline.pop("max_wall_seconds")
    if actual != baseline or not (
        baseline_wall <= wall <= PHASE8_MAX_OWNER_WALL_SECONDS
    ):
        raise PipelineError("certified issue lane found a changed safety budget")

    resolved_cache = (repo_root / cache_root).resolve()
    proof, blobs = verifier(
        state=state,
        cache_root=resolved_cache,
        run_id=run_id,
    )
    usage = _scan_attempt_usage_for_run(state, run_id)
    by_task = {}
    for item in proof["proofs"]:
        by_task.setdefault(item["task_id"], item)
    incomplete = [
        item for item in by_task.values()
        if state.connection.execute(
            "SELECT status FROM tasks WHERE task_id=?",
            (item["task_id"],),
        ).fetchone()[0] != "complete"
    ]
    _enforce_scan_attempt_budgets(
        usage, planned_attempts=len(incomplete), budgets=budgets
    )
    if not incomplete:
        return {
            "run_id": run_id,
            "proof_sha256": proof["contract_sha256"],
            "completed": len(by_task),
            "scanned": 0,
            "launchd_armed": False,
        }

    charged = float(execution.get("historical_wall_seconds", 0) or 0)
    try:
        started = datetime.datetime.fromisoformat(
            str(run["started_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise PipelineError("certified issue run start time is invalid") from exc
    elapsed = max(
        0.0,
        (
            datetime.datetime.now(datetime.timezone.utc) - started
        ).total_seconds(),
    )
    remaining_wall = wall - charged - elapsed
    if remaining_wall <= budgets.repo_timeout_seconds:
        raise PipelineError("certified issue lane lacks one repository wall")
    run_deadline = time.monotonic() + remaining_wall

    active_ids = set(execution.get("selected_library_ids") or ())
    selected_libraries = [
        library for library in config.LIBRARIES
        if library["id"] in active_ids
    ]
    active_plan = build_plan(
        mode="reconcile",
        state_path=(repo_root / state_path).resolve(),
        data_dir=(repo_root / data_dir).resolve(),
        libraries=config.LIBRARIES,
        weekly_scan_budget=budgets.max_scan_repositories,
        max_graphql_points=budgets.max_graphql_points,
        min_graphql_remaining=budgets.min_graphql_remaining,
    )
    if active_plan.fingerprints.as_dict() != fingerprints:
        raise PipelineError("certified issue plan fingerprints changed")
    pipeline = CollectorPipeline(
        repo_root=repo_root,
        state_path=state_path,
        cache_root=cache_root,
        data_dir=data_dir,
        scan_runner=_single_process_runner,
    )
    pipeline._active_plan = active_plan

    completed_task_ids = []
    with override(resolved_cache, blobs):
        for item in incomplete:
            task = state.connection.execute(
                "SELECT status,attempts FROM tasks WHERE task_id=?",
                (item["task_id"],),
            ).fetchone()
            attempts = int(task["attempts"])
            if attempts >= _MAX_CERTIFIED_ATTEMPTS:
                raise PipelineError(
                    "certified issue lane exhausted its attempts"
                )
            now = (
                datetime.datetime.now(datetime.timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
            with state.transaction(immediate=True):
                changed = state.connection.execute(
                    """
                    UPDATE tasks SET status='pending', max_attempts=?,
                        lease_owner=NULL, lease_expires_at=NULL,
                        available_at=0, error_code=?,
                        updated_at=?, finished_at=NULL
                    WHERE task_id=? AND status IN ('failed','pending')
                      AND attempts=?
                    """,
                    (
                        _MAX_CERTIFIED_ATTEMPTS,
                        "issue_retry:" + retry_label,
                        now,
                        item["task_id"],
                        attempts,
                    ),
                ).rowcount
                if changed != 1:
                    raise PipelineError(
                        "certified issue task changed during retry"
                    )
            row = state.connection.execute(
                "SELECT * FROM repositories WHERE node_id=?",
                (item["repository_id"],),
            ).fetchone()
            publishable = {item["full_name"]: _metadata(row)}
            grouped = {
                item["full_name"]: set(item["candidate_library_ids"])
            }
            _outcomes, scanned = pipeline._scan(
                state,
                run_id,
                selected_libraries,
                grouped,
                publishable,
                budgets,
                retirement_library_ids=(),
                run_deadline=run_deadline,
                retry_workers=1,
                defer_issue_lane=False,
                initial_workers=1,
                preserve_task_universe=True,
            )
            if scanned != 1:
                raise PipelineError("certified issue scan count changed")
            completed_task_ids.append(item["task_id"])

    success_rows = []
    for item in by_task.values():
        task = state.connection.execute(
            "SELECT status,attempts,result_json FROM tasks WHERE task_id=?",
            (item["task_id"],),
        ).fetchone()
        if task["status"] != "complete" or task["result_json"] is None:
            raise PipelineError("certified issue recovery remains incomplete")
        success_rows.append({
            "task_id": item["task_id"],
            "attempt": int(task["attempts"]),
            "result_sha256": hashlib.sha256(
                task["result_json"].encode("utf-8")
            ).hexdigest(),
        })
    checkpoint = {
        "version": 1,
        "proof": proof,
        "successful_tasks": success_rows,
        "successful_tasks_sha256": _sha256(success_rows),
        "completed_checkpoint_replayed": 0,
        "other_budget_changes": 0,
    }
    state.update_stage(
        run_id,
        stage_name,
        status="complete",
        counters={
            counter_name: len(success_rows),
            "newly_scanned": len(completed_task_ids),
        },
        metrics={
            "completed_checkpoint_replayed": 0,
            "other_budget_changes": 0,
        },
        checkpoint=checkpoint,
    )
    return {
        "run_id": run_id,
        "proof_sha256": proof["contract_sha256"],
        "completed": len(success_rows),
        "scanned": len(completed_task_ids),
        "launchd_armed": False,
    }


def run_notebook_issue_lane(
    *,
    state: StateDB,
    repo_root: Path,
    state_path: str,
    cache_root: str,
    data_dir: str,
    run_id: str,
) -> dict[str, Any]:
    """Certify and rescan only exact malformed-notebook tasks."""

    def override(_cache_root, blobs):
        return _exact_notebook_negatives(blobs)

    return _run_certified_issue_lane(
        state=state,
        repo_root=repo_root,
        state_path=state_path,
        cache_root=cache_root,
        data_dir=data_dir,
        run_id=run_id,
        verifier=verify_notebook_negative_contract,
        override=override,
        retry_label="notebook_proof",
        stage_name="phase8_notebook_issue_lane",
        counter_name="certified_notebook_tasks",
    )


def run_blocked_lfs_inspection_issue_lane(
    *,
    state: StateDB,
    repo_root: Path,
    state_path: str,
    cache_root: str,
    data_dir: str,
    run_id: str,
) -> dict[str, Any]:
    """Certify and rescan exact macOS-denied LFS precheck paths."""
    return _run_certified_issue_lane(
        state=state,
        repo_root=repo_root,
        state_path=state_path,
        cache_root=cache_root,
        data_dir=data_dir,
        run_id=run_id,
        verifier=verify_blocked_lfs_inspection_contract,
        override=_exact_blocked_worktree_reads,
        retry_label="blocked_lfs_inspection_proof",
        stage_name="phase8_lfs_inspection_issue_lane",
        counter_name="certified_lfs_inspection_tasks",
    )
