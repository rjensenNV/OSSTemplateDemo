"""Transactional operational state for the REQ-14 collector.

This module is intentionally stdlib-only and independent from network and
collector modules.  It is safe to exercise in tests without touching
``data/``.  The public-repository admission boundary fails closed: metadata
without an explicit ``visibility == "public"`` is purged rather than stored.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import sqlite3
import time
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import state_migrations


CHECKPOINT_FORMAT_VERSION = 1
CHECKPOINT_TARGET_BYTES = 3_999_999
CHECKPOINT_HARD_BYTES = 5 * 1024 * 1024
_REPOSITORY_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"(?![A-Za-z0-9_.-])"
)
_CHECKPOINT_DROP = object()
_SCAN_ATTEMPT_FLOAT_FIELDS = (
    "seconds",
    "current_tree_triage_seconds",
    "history_dating_seconds",
    "analysis_seconds",
)
_SCAN_ATTEMPT_COUNT_FIELDS = (
    "git_subprocess_count",
    "network_clone_count",
    "network_fetch_count",
    "network_materialized_bytes",
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _json(value: Any) -> str:
    return canonical_json({} if value is None else value)


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _validate_public_payload(value: Any, *, path: str = "payload") -> None:
    """Reject explicit private/unknown visibility markers in persisted payloads."""
    if isinstance(value, Mapping):
        lowered = {str(key).lower(): item for key, item in value.items()}
        if "visibility" in lowered and str(lowered["visibility"]).lower() != "public":
            raise ValueError(f"{path} contains non-public visibility")
        for flag in ("private", "is_private", "visibility_excluded"):
            if lowered.get(flag) not in (None, False, 0, ""):
                raise ValueError(f"{path} contains a private marker")
        if "is_public" in lowered and lowered["is_public"] is not True:
            raise ValueError(f"{path} contains a non-public marker")
        for key, item in value.items():
            _validate_public_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_public_payload(item, path=f"{path}[{index}]")


def _checkpoint_public_identities(
    repository_rows: Sequence[Mapping[str, Any]],
) -> tuple[frozenset[str], frozenset[str]]:
    """Return current public node/name identities plus same-node request aliases."""
    node_ids: set[str] = set()
    names: set[str] = set()

    def add_identity(value: Mapping[str, Any]) -> None:
        for key in ("node_id", "requested_node_id"):
            node_id = value.get(key)
            if isinstance(node_id, str) and node_id:
                node_ids.add(node_id)
        for key in ("full_name", "requested_full_name"):
            full_name = value.get(key)
            if isinstance(full_name, str) and full_name:
                names.add(full_name.casefold())

    for row in repository_rows:
        if row.get("visibility") != "public":
            continue
        add_identity(row)
        try:
            metadata = json.loads(str(row.get("metadata_json") or "{}"))
        except (TypeError, ValueError):
            continue
        if isinstance(metadata, Mapping):
            add_identity(metadata)
            nested = metadata.get("metadata")
            if isinstance(nested, Mapping):
                add_identity(nested)
    return frozenset(node_ids), frozenset(names)


def _checkpoint_identity_is_public(
    value: Mapping[str, Any],
    *,
    public_node_ids: frozenset[str],
    public_names: frozenset[str],
) -> bool:
    node_values = (
        value.get("node_id"),
        value.get("repo_node_id"),
        value.get("repository_id"),
        value.get("requested_node_id"),
    )
    if any(
        isinstance(node_id, str) and node_id in public_node_ids
        for node_id in node_values
    ):
        return True
    name_values = (
        value.get("full_name"),
        value.get("repo_full_name"),
        value.get("repository_full_name"),
        value.get("requested_full_name"),
    )
    return any(
        isinstance(full_name, str)
        and full_name.casefold() in public_names
        for full_name in name_values
    )


def _redact_checkpoint_diagnostic(
    value: Any,
    *,
    public_names: frozenset[str],
) -> Any:
    """Remove unadmitted OWNER/REPO-like tokens from diagnostic-only fields."""
    if isinstance(value, str):
        return _REPOSITORY_TOKEN.sub(
            lambda match: (
                match.group(1)
                if match.group(1).casefold() in public_names
                else "[REDACTED REPOSITORY]"
            ),
            value,
        )
    if isinstance(value, list):
        return [
            _redact_checkpoint_diagnostic(
                item,
                public_names=public_names,
            )
            for item in value
        ]
    if isinstance(value, Mapping):
        return {
            str(key): _redact_checkpoint_diagnostic(
                item,
                public_names=public_names,
            )
            for key, item in value.items()
        }
    return value


def _sanitize_checkpoint_diagnostics(
    value: Any,
    *,
    public_names: frozenset[str],
) -> Any:
    """Recursively redact identity-like tokens only inside diagnostic fields."""
    if isinstance(value, Mapping):
        sanitized = {}
        for key, item in value.items():
            rendered_key = str(key)
            if rendered_key.casefold() in {
                "detail",
                "diagnostic",
                "error",
                "errors",
                "message",
            }:
                sanitized[rendered_key] = _redact_checkpoint_diagnostic(
                    item,
                    public_names=public_names,
                )
            else:
                sanitized[rendered_key] = _sanitize_checkpoint_diagnostics(
                    item,
                    public_names=public_names,
                )
        return sanitized
    if isinstance(value, list):
        return [
            _sanitize_checkpoint_diagnostics(
                item,
                public_names=public_names,
            )
            for item in value
        ]
    return value


def _sanitize_checkpoint_identity_records(
    value: Any,
    *,
    public_node_ids: frozenset[str],
    public_names: frozenset[str],
) -> Any:
    """Drop structured records whose repository identity is not admitted."""
    if isinstance(value, Mapping):
        identity_fields = {
            "full_name",
            "repo_full_name",
            "repository_full_name",
            "node_id",
            "repo_node_id",
            "repository_id",
            "requested_full_name",
            "requested_node_id",
        }
        if identity_fields.intersection(str(key) for key in value) and not (
            _checkpoint_identity_is_public(
                value,
                public_node_ids=public_node_ids,
                public_names=public_names,
            )
        ):
            return _CHECKPOINT_DROP
        result = {}
        for key, item in value.items():
            sanitized = _sanitize_checkpoint_identity_records(
                item,
                public_node_ids=public_node_ids,
                public_names=public_names,
            )
            if sanitized is not _CHECKPOINT_DROP:
                result[str(key)] = sanitized
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            sanitized = _sanitize_checkpoint_identity_records(
                item,
                public_node_ids=public_node_ids,
                public_names=public_names,
            )
            if sanitized is not _CHECKPOINT_DROP:
                result.append(sanitized)
        return result
    return value


def _sanitize_discovery_task_result(
    value: Mapping[str, Any],
    *,
    public_node_ids: frozenset[str],
    public_names: frozenset[str],
) -> dict[str, Any]:
    result = dict(value)
    removed = 0
    for field in ("observations", "quarantined_observations"):
        observations = result.get(field)
        if not isinstance(observations, list):
            continue
        admitted = [
            dict(observation)
            for observation in observations
            if isinstance(observation, Mapping)
            and _checkpoint_identity_is_public(
                observation,
                public_node_ids=public_node_ids,
                public_names=public_names,
            )
        ]
        removed += len(observations) - len(admitted)
        result[field] = admitted
    certificate = result.get("certificate")
    if isinstance(certificate, Mapping):
        certificate = dict(certificate)
        certificate["observations_count"] = len(
            result.get("observations") or ()
        )
        if removed:
            metrics = certificate.get("metrics")
            metrics = dict(metrics) if isinstance(metrics, Mapping) else {}
            metrics["checkpoint_redacted_observations"] = removed
            certificate["metrics"] = metrics
        result["certificate"] = certificate
    return result


def _sanitize_metadata_task_documents(
    payload: Mapping[str, Any],
    result: Mapping[str, Any] | None,
    *,
    public_node_ids: frozenset[str],
    public_names: frozenset[str],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    result_copy = dict(result) if isinstance(result, Mapping) else None
    safe_request_keys: set[str] = set()
    if result_copy is not None:
        repositories = result_copy.get("repositories")
        admitted = []
        if isinstance(repositories, list):
            for repository in repositories:
                if (
                    not isinstance(repository, Mapping)
                    or repository.get("admitted_public") is not True
                    or not _checkpoint_identity_is_public(
                        repository,
                        public_node_ids=public_node_ids,
                        public_names=public_names,
                    )
                ):
                    continue
                item = dict(repository)
                admitted.append(item)
                request_key = item.get("request_key")
                if isinstance(request_key, str):
                    safe_request_keys.add(request_key)
            result_copy["repositories"] = admitted

    payload_copy = dict(payload)
    lookups = payload_copy.get("lookups")
    if isinstance(lookups, list):
        admitted_lookups = []
        for lookup in lookups:
            if not isinstance(lookup, Mapping):
                continue
            request_key = (
                "node:" + str(lookup.get("node_id"))
                if lookup.get("node_id")
                else "name:" + str(lookup.get("full_name"))
            )
            if (
                request_key in safe_request_keys
                or _checkpoint_identity_is_public(
                    lookup,
                    public_node_ids=public_node_ids,
                    public_names=public_names,
                )
            ):
                admitted_lookups.append(dict(lookup))
        payload_copy["lookups"] = admitted_lookups
    return payload_copy, result_copy


def _sanitize_checkpoint_task_row(
    row: Mapping[str, Any],
    *,
    public_node_ids: frozenset[str],
    public_names: frozenset[str],
) -> dict[str, Any] | None:
    """Sanitize committed task journals without mutating resumable local state."""
    result = dict(row)
    repository_id = result.get("repository_id")
    if (
        isinstance(repository_id, str)
        and repository_id not in public_node_ids
    ):
        return None
    try:
        payload = json.loads(str(result.get("payload_json") or "{}"))
        raw_result = result.get("result_json")
        task_result = (
            None if raw_result is None else json.loads(str(raw_result))
        )
    except (TypeError, ValueError):
        # Malformed local journals cannot be made safe by guessing.
        return None
    if not isinstance(payload, Mapping) or (
        task_result is not None and not isinstance(task_result, Mapping)
    ):
        return None

    stage = result.get("stage")
    if stage in {
        "github-metadata-batch",
        "github-final-visibility-batch",
    }:
        payload, task_result = _sanitize_metadata_task_documents(
            payload,
            task_result,
            public_node_ids=public_node_ids,
            public_names=public_names,
        )
    elif stage == "discovery-query":
        payload = dict(payload)
        if task_result is not None:
            task_result = _sanitize_discovery_task_result(
                task_result,
                public_node_ids=public_node_ids,
                public_names=public_names,
            )
    elif repository_id is None:
        # Unknown unlinked task schemas cannot prove their repository identity.
        payload = {}
        task_result = None
    else:
        payload = dict(payload)
        task_result = (
            dict(task_result) if task_result is not None else None
        )

    payload = _sanitize_checkpoint_diagnostics(
        payload,
        public_names=public_names,
    )
    task_result = (
        _sanitize_checkpoint_diagnostics(
            task_result,
            public_names=public_names,
        )
        if task_result is not None
        else None
    )
    result["payload_json"] = canonical_json(payload)
    result["result_json"] = (
        None if task_result is None else canonical_json(task_result)
    )
    return result


def _sanitize_checkpoint_operational_row(
    table: str,
    row: Mapping[str, Any],
    *,
    public_node_ids: frozenset[str],
    public_names: frozenset[str],
) -> dict[str, Any] | None:
    """Apply the public identity boundary to non-relational journal fields."""
    if table == "tasks":
        return _sanitize_checkpoint_task_row(
            row,
            public_node_ids=public_node_ids,
            public_names=public_names,
        )
    if table == "scan_attempts":
        result = dict(row)
        if result.get("repository_id") not in public_node_ids:
            return None
        result["error_detail"] = _redact_checkpoint_diagnostic(
            result.get("error_detail"),
            public_names=public_names,
        )
        return result
    result = dict(row)
    columns = {
        "runs": ("plan_json",),
        "stages": (
            "counters_json",
            "metrics_json",
            "checkpoint_json",
        ),
    }.get(table, ())
    for column in columns:
        try:
            value = json.loads(str(result.get(column) or "{}"))
        except (TypeError, ValueError):
            return None
        value = _sanitize_checkpoint_identity_records(
            value,
            public_node_ids=public_node_ids,
            public_names=public_names,
        )
        if value is _CHECKPOINT_DROP:
            value = {}
        value = _sanitize_checkpoint_diagnostics(
            value,
            public_names=public_names,
        )
        result[column] = canonical_json(value)
    return result


def _require_public_repository(
    connection: sqlite3.Connection, repository_id: str
) -> None:
    row = connection.execute(
        "SELECT visibility FROM repositories WHERE node_id=?", (repository_id,)
    ).fetchone()
    if row is None or row["visibility"] != "public":
        raise ValueError("repository is not explicitly public")


def _scan_attempt_usage_values(
    result: Mapping[str, Any] | None,
) -> tuple[dict[str, int | float | None], bool]:
    """Extract only complete, non-negative aggregate scanner usage."""
    result = result if isinstance(result, Mapping) else {}
    values: dict[str, int | float | None] = {}
    complete = True
    for field in _SCAN_ATTEMPT_FLOAT_FIELDS:
        value = result.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            values[field] = None
            complete = False
        else:
            values[field] = float(value)
    for field in _SCAN_ATTEMPT_COUNT_FIELDS:
        value = result.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            values[field] = None
            complete = False
        else:
            values[field] = int(value)
    return values, complete


class StateDB:
    """A single-coordinator SQLite state handle.

    Connections use autocommit so every mutation either has its own short
    transaction or is explicitly grouped with :meth:`transaction`.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        now=utc_now,
        auto_migrate: bool = True,
    ) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._now = now
        self._transaction_depth = 0
        self.connection = sqlite3.connect(
            self.path,
            timeout=30.0,
            isolation_level=None,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 30000")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = FULL")
        if auto_migrate:
            self.migrate()

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    @property
    def schema_version(self) -> int:
        return state_migrations.current_version(self.connection)

    def migrate(
        self, backup_destination: str | os.PathLike[str] | None = None
    ) -> int:
        """Apply pending migrations, backing up any non-pristine DB first."""
        pending = state_migrations.pending_versions(self.connection)
        if not pending:
            return self.schema_version
        user_objects = self.connection.execute(
            """
            SELECT COUNT(*) FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'index', 'trigger')
            """
        ).fetchone()[0]
        explicit_destination = (
            Path(backup_destination).expanduser().resolve()
            if backup_destination is not None
            else None
        )

        def backup_before(current: int, target: int) -> None:
            # A brand-new empty DB has nothing to preserve.  Every subsequent
            # step gets its own recoverable pre-migration image.
            if current == 0 and not user_objects:
                return
            if explicit_destination is not None and len(pending) == 1:
                destination = explicit_destination
            elif explicit_destination is not None:
                destination = explicit_destination.with_name(
                    f"{explicit_destination.name}.v{current}-to-v{target}"
                )
            else:
                destination = self.path.with_name(
                    f"{self.path.name}.pre-migration-v{current}-to-v{target}.backup"
                )
            self.backup(destination)

        return state_migrations.apply_migrations(
            self.connection,
            now=self._now,
            before_migration=backup_before,
        )

    @contextlib.contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Run a safe transaction, using savepoints for nested helpers."""
        depth = self._transaction_depth
        savepoint = f"state_nested_{depth}"
        self._transaction_depth += 1
        try:
            if depth == 0:
                self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            else:
                self.connection.execute(f"SAVEPOINT {savepoint}")
            yield self.connection
            if depth == 0:
                self.connection.commit()
            else:
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        except BaseException:
            if depth == 0:
                self.connection.rollback()
            else:
                self.connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        finally:
            self._transaction_depth -= 1

    def integrity_check(self) -> str:
        return str(self.connection.execute("PRAGMA integrity_check").fetchone()[0])

    def backup(self, destination: str | os.PathLike[str]) -> Path:
        """Create a consistent SQLite backup without copying WAL files."""
        if self._transaction_depth:
            raise RuntimeError("cannot back up state from inside a write transaction")
        target = Path(destination).expanduser().resolve()
        if target == self.path:
            raise ValueError("backup destination must differ from state database")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.tmp-{os.getpid()}")
        if tmp.exists():
            tmp.unlink()
        backup_connection = sqlite3.connect(tmp)
        try:
            self.connection.backup(backup_connection)
            check = backup_connection.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                raise RuntimeError(f"state backup integrity check failed: {check}")
        except BaseException:
            backup_connection.close()
            if tmp.exists():
                tmp.unlink()
            raise
        finally:
            if backup_connection:
                backup_connection.close()
        os.replace(tmp, target)
        return target

    def _purge_repository(self, *, node_id: str | None, full_name: str | None) -> None:
        with self.transaction(immediate=True):
            if node_id:
                self.connection.execute(
                    "DELETE FROM repositories WHERE node_id = ?", (node_id,)
                )
            if full_name:
                self.connection.execute(
                    "DELETE FROM repositories WHERE full_name = ?", (full_name,)
                )

    def upsert_repository(self, metadata: Mapping[str, Any]) -> str | None:
        """Admit explicit public metadata, or quarantine it by deleting prior state.

        ``None`` means the row was not admitted.  The non-public repository name
        is never written to a quarantine/log table.
        """
        node_id = str(metadata.get("node_id") or "").strip() or None
        full_name = str(metadata.get("full_name") or "").strip() or None
        visibility = str(metadata.get("visibility") or "").strip().lower()
        if visibility != "public":
            self._purge_repository(node_id=node_id, full_name=full_name)
            return None
        if not node_id or not full_name:
            raise ValueError("public repository requires node_id and full_name")
        _validate_public_payload(metadata, path="repository")
        now = self._now()
        metadata_json = _json(metadata.get("metadata", {}))
        with self.transaction(immediate=True):
            # GitHub node IDs survive renames.  Remove an obsolete name collision
            # only when it belongs to this same public node.
            collision = self.connection.execute(
                "SELECT node_id FROM repositories WHERE full_name = ?", (full_name,)
            ).fetchone()
            if collision is not None and collision["node_id"] != node_id:
                raise ValueError("public repository name belongs to a different node ID")
            self.connection.execute(
                """
                INSERT INTO repositories(
                    node_id, full_name, visibility, is_fork, is_archived,
                    default_branch, head_sha, metadata_json, etag,
                    first_seen_at, last_seen_at, metadata_checked_at
                ) VALUES (?, ?, 'public', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    full_name=excluded.full_name,
                    visibility='public',
                    is_fork=excluded.is_fork,
                    is_archived=excluded.is_archived,
                    default_branch=excluded.default_branch,
                    head_sha=excluded.head_sha,
                    metadata_json=excluded.metadata_json,
                    etag=excluded.etag,
                    last_seen_at=excluded.last_seen_at,
                    metadata_checked_at=excluded.metadata_checked_at
                """,
                (
                    node_id,
                    full_name,
                    int(bool(metadata.get("is_fork", False))),
                    int(bool(metadata.get("is_archived", False))),
                    metadata.get("default_branch"),
                    metadata.get("head_sha"),
                    metadata_json,
                    metadata.get("etag"),
                    now,
                    str(metadata.get("last_seen_at") or now),
                    str(metadata.get("metadata_checked_at") or now),
                ),
            )
        return node_id

    def get_repository(self, node_id: str) -> dict[str, Any] | None:
        return _row_dict(
            self.connection.execute(
                "SELECT * FROM repositories WHERE node_id = ?", (node_id,)
            ).fetchone()
        )

    def upsert_library(
        self,
        library_id: str,
        *,
        catalog: Mapping[str, Any],
        fingerprints: Mapping[str, str],
        active: bool = True,
    ) -> None:
        required = {
            "discovery",
            "detector",
            "citation",
            "dating",
            "aggregation",
            "presentation",
            "release",
        }
        missing = required.difference(fingerprints)
        if missing:
            raise ValueError(f"missing library fingerprints: {sorted(missing)}")
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                INSERT INTO libraries(
                    library_id, catalog_json, discovery_fp, detector_fp,
                    citation_fp, dating_fp, aggregation_fp, presentation_fp,
                    release_fp, active, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(library_id) DO UPDATE SET
                    catalog_json=excluded.catalog_json,
                    discovery_fp=excluded.discovery_fp,
                    detector_fp=excluded.detector_fp,
                    citation_fp=excluded.citation_fp,
                    dating_fp=excluded.dating_fp,
                    aggregation_fp=excluded.aggregation_fp,
                    presentation_fp=excluded.presentation_fp,
                    release_fp=excluded.release_fp,
                    active=excluded.active,
                    updated_at=excluded.updated_at
                """,
                (
                    library_id,
                    _json(catalog),
                    fingerprints["discovery"],
                    fingerprints["detector"],
                    fingerprints["citation"],
                    fingerprints["dating"],
                    fingerprints["aggregation"],
                    fingerprints["presentation"],
                    fingerprints["release"],
                    int(active),
                    self._now(),
                ),
            )

    def record_catalog_events(
        self, events: Sequence[Mapping[str, Any]]
    ) -> int:
        """Persist immutable catalog observations without rewriting history."""
        required = {
            "library_id",
            "catalog_version",
            "observed_on",
            "event",
            "name",
            "catalog_status",
            "source",
            "provenance",
            "effective_on",
            "note",
        }
        inserted = 0
        with self.transaction(immediate=True):
            for event in events:
                if set(event) != required:
                    raise ValueError("catalog event shape is invalid")
                _validate_public_payload(event, path="catalog.event")
                if self.connection.execute(
                    "SELECT 1 FROM libraries WHERE library_id=?",
                    (event["library_id"],),
                ).fetchone() is None:
                    raise KeyError(
                        "catalog event references unknown library: "
                        + str(event["library_id"])
                    )
                existing = self.connection.execute(
                    """
                    SELECT name, catalog_status, source, provenance,
                           effective_on, note
                    FROM catalog_events
                    WHERE library_id=? AND catalog_version=?
                      AND observed_on=? AND event=?
                    """,
                    (
                        event["library_id"],
                        event["catalog_version"],
                        event["observed_on"],
                        event["event"],
                    ),
                ).fetchone()
                values = (
                    event["name"],
                    event["catalog_status"],
                    event["source"],
                    event["provenance"],
                    event["effective_on"],
                    event["note"],
                )
                if existing is not None:
                    if tuple(existing) != values:
                        raise ValueError(
                            "immutable catalog event changed: "
                            + str(event["library_id"])
                        )
                    continue
                self.connection.execute(
                    """
                    INSERT INTO catalog_events(
                        library_id, catalog_version, observed_on, event, name,
                        catalog_status, source, provenance, effective_on, note,
                        recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event["library_id"],
                        event["catalog_version"],
                        event["observed_on"],
                        event["event"],
                        *values,
                        self._now(),
                    ),
                )
                inserted += 1
        return inserted

    def add_candidate(
        self,
        *,
        repository_id: str,
        library_id: str,
        source: str,
        query_fp: str,
        coverage_epoch: str,
        signal: str = "",
        path: str = "",
        ref: str = "",
        state: str = "active",
    ) -> int:
        now = self._now()
        with self.transaction(immediate=True):
            _require_public_repository(self.connection, repository_id)
            self.connection.execute(
                """
                INSERT INTO candidates(
                    repository_id, library_id, source, query_fp, signal, path,
                    ref, first_seen_at, last_seen_at, coverage_epoch, state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository_id, library_id, source, query_fp, signal, path, ref)
                DO UPDATE SET
                    last_seen_at=excluded.last_seen_at,
                    coverage_epoch=excluded.coverage_epoch,
                    state=excluded.state
                """,
                (
                    repository_id,
                    library_id,
                    source,
                    query_fp,
                    signal,
                    path,
                    ref,
                    now,
                    now,
                    coverage_epoch,
                    state,
                ),
            )
            result = self.connection.execute(
                """
                SELECT candidate_id FROM candidates
                WHERE repository_id=? AND library_id=? AND source=? AND query_fp=?
                  AND signal=? AND path=? AND ref=?
                """,
                (repository_id, library_id, source, query_fp, signal, path, ref),
            ).fetchone()
            return int(result["candidate_id"])

    def retire_candidates(
        self,
        *,
        repository_id: str,
        library_id: str,
        coverage_epoch: str,
    ) -> int:
        """Deactivate fully reverified absent evidence; rediscovery reactivates it."""
        with self.transaction(immediate=True):
            _require_public_repository(self.connection, repository_id)
            return self.connection.execute(
                """
                UPDATE candidates
                SET state='rejected', coverage_epoch=?, last_seen_at=?
                WHERE repository_id=? AND library_id=? AND state='active'
                """,
                (
                    coverage_epoch,
                    self._now(),
                    repository_id,
                    library_id,
                ),
            ).rowcount

    def record_scan_result(
        self,
        *,
        repository_id: str,
        library_id: str,
        head_sha: str,
        detector_fp: str,
        classification: str,
        status: str,
        evidence: Mapping[str, Any] | None = None,
        raw_first_commit: str | None = None,
        raw_first_date: str | None = None,
        derived_first_date: str | None = None,
    ) -> int:
        evidence = evidence or {}
        _validate_public_payload(evidence, path="scan.evidence")
        with self.transaction(immediate=True):
            _require_public_repository(self.connection, repository_id)
            self.connection.execute(
                """
                INSERT INTO scan_results(
                    repository_id, library_id, head_sha, detector_fp,
                    classification, status, evidence_json, raw_first_commit,
                    raw_first_date, derived_first_date, scanned_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository_id, library_id, head_sha, detector_fp)
                DO UPDATE SET
                    classification=excluded.classification,
                    status=excluded.status,
                    evidence_json=excluded.evidence_json,
                    raw_first_commit=excluded.raw_first_commit,
                    raw_first_date=excluded.raw_first_date,
                    derived_first_date=excluded.derived_first_date,
                    scanned_at=excluded.scanned_at
                """,
                (
                    repository_id,
                    library_id,
                    head_sha,
                    detector_fp,
                    classification,
                    status,
                    _json(evidence),
                    raw_first_commit,
                    raw_first_date,
                    derived_first_date,
                    self._now(),
                ),
            )
            row = self.connection.execute(
                """
                SELECT scan_result_id FROM scan_results
                WHERE repository_id=? AND library_id=? AND head_sha=? AND detector_fp=?
                """,
                (repository_id, library_id, head_sha, detector_fp),
            ).fetchone()
            return int(row["scan_result_id"])

    def positive_scan_results_needing_redate(
        self, *, dating_fp: str
    ) -> list[dict[str, Any]]:
        """Return current positive verdicts whose derived dating is stale.

        Dating is deliberately not part of detector validity.  These rows
        retain the raw first-use commit/date needed to re-derive publication
        fields without checking out or rescanning the repository.
        """
        if not isinstance(dating_fp, str) or not dating_fp:
            raise ValueError("dating fingerprint must be a non-empty string")
        rows = self.connection.execute(
            """
            SELECT s.*
            FROM scan_results s
            JOIN repositories r
              ON r.node_id=s.repository_id AND r.head_sha=s.head_sha
            JOIN libraries l
              ON l.library_id=s.library_id
             AND l.detector_fp=s.detector_fp
            WHERE s.status='clean' AND s.classification!='rejected'
            ORDER BY s.repository_id, s.library_id, s.scan_result_id
            """
        ).fetchall()
        pending = []
        for row in rows:
            try:
                evidence = json.loads(row["evidence_json"] or "{}")
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "positive scan evidence is not valid JSON"
                ) from exc
            if not isinstance(evidence, dict):
                raise ValueError("positive scan evidence must be an object")
            if evidence.get("_dating_fp") == dating_fp:
                continue
            item = _row_dict(row)
            item["evidence"] = evidence
            pending.append(item)
        return pending

    def prior_first_use_boundaries(
        self,
        *,
        repository_id: str,
        current_head_sha: str,
        detector_fingerprints: Mapping[str, str],
    ) -> dict[str, dict[str, Any]]:
        """Return the latest valid private proof per library before this HEAD.

        Detector identity is required in addition to the scanner's whole-plan
        signature. This prevents an old detector's positive row from becoming
        an optimization input after its evidence semantics change.
        """
        if not detector_fingerprints:
            return {}
        library_ids = sorted({
            str(library_id)
            for library_id, detector_fp in detector_fingerprints.items()
            if (
                isinstance(library_id, str)
                and library_id
                and isinstance(detector_fp, str)
                and detector_fp
            )
        })
        if not library_ids:
            return {}
        placeholders = ",".join("?" for _ in library_ids)
        rows = self.connection.execute(
            """
            SELECT library_id, detector_fp, evidence_json
            FROM scan_results
            WHERE repository_id=?
              AND head_sha<>?
              AND status='clean'
              AND classification<>'rejected'
              AND library_id IN (%s)
            ORDER BY scanned_at DESC, scan_result_id DESC
            """ % placeholders,
            (repository_id, current_head_sha, *library_ids),
        ).fetchall()
        found = {}
        for row in rows:
            library_id = row["library_id"]
            if library_id in found:
                continue
            if (
                row["detector_fp"]
                != detector_fingerprints.get(library_id)
            ):
                continue
            try:
                evidence = json.loads(row["evidence_json"] or "{}")
            except (TypeError, ValueError):
                # Historical corruption/non-boundary rows are not reusable;
                # complete dating remains the correctness fallback.
                continue
            boundaries = (
                evidence.get("_first_use_boundaries")
                if isinstance(evidence, dict)
                else None
            )
            if isinstance(boundaries, dict) and boundaries:
                found[library_id] = boundaries
        return found

    def redate_positive_scan_result(
        self, scan_result_id: int, *, dating_fp: str
    ) -> None:
        """Re-derive one positive row from persisted raw first-use evidence."""
        if not isinstance(dating_fp, str) or not dating_fp:
            raise ValueError("dating fingerprint must be a non-empty string")
        with self.transaction(immediate=True):
            row = self.connection.execute(
                """
                SELECT * FROM scan_results
                WHERE scan_result_id=? AND status='clean'
                  AND classification!='rejected'
                """,
                (int(scan_result_id),),
            ).fetchone()
            if row is None:
                raise KeyError("unknown current positive scan result")
            try:
                evidence = json.loads(row["evidence_json"] or "{}")
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "positive scan evidence is not valid JSON"
                ) from exc
            if not isinstance(evidence, dict):
                raise ValueError("positive scan evidence must be an object")
            raw_first_date = row["raw_first_date"]
            if raw_first_date is None:
                raw_first_date = evidence.get("first_integration")
            if not isinstance(raw_first_date, str) or not raw_first_date:
                raise ValueError(
                    "positive scan result lacks persisted raw first-use date"
                )
            evidence["first_integration"] = raw_first_date
            evidence["_dating_fp"] = dating_fp
            _validate_public_payload(evidence, path="scan.evidence")
            changed = self.connection.execute(
                """
                UPDATE scan_results
                SET evidence_json=?, derived_first_date=?
                WHERE scan_result_id=? AND status='clean'
                  AND classification!='rejected'
                """,
                (_json(evidence), raw_first_date, int(scan_result_id)),
            ).rowcount
            if changed != 1:
                raise RuntimeError("positive scan result changed during redating")

    def record_repo_analysis(
        self,
        *,
        repository_id: str,
        head_sha: str,
        ai_fp: str,
        cff_fp: str,
        analysis: Mapping[str, Any] | None,
        status: str,
    ) -> int:
        analysis = analysis or {}
        _validate_public_payload(analysis, path="repo_analysis")
        with self.transaction(immediate=True):
            _require_public_repository(self.connection, repository_id)
            self.connection.execute(
                """
                INSERT INTO repo_analysis(
                    repository_id, head_sha, ai_fp, cff_fp, analysis_json,
                    status, analyzed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository_id, head_sha, ai_fp, cff_fp) DO UPDATE SET
                    analysis_json=excluded.analysis_json,
                    status=excluded.status,
                    analyzed_at=excluded.analyzed_at
                """,
                (
                    repository_id,
                    head_sha,
                    ai_fp,
                    cff_fp,
                    _json(analysis),
                    status,
                    self._now(),
                ),
            )
            row = self.connection.execute(
                """
                SELECT analysis_id FROM repo_analysis
                WHERE repository_id=? AND head_sha=? AND ai_fp=? AND cff_fp=?
                """,
                (repository_id, head_sha, ai_fp, cff_fp),
            ).fetchone()
            return int(row["analysis_id"])

    def create_run(
        self,
        run_id: str,
        *,
        mode: str,
        plan: Mapping[str, Any] | None = None,
        budgets: Mapping[str, Any] | None = None,
        fingerprints: Mapping[str, Any] | None = None,
        base_release_id: str | None = None,
        status: str = "planned",
    ) -> None:
        _validate_public_payload(plan or {}, path="run.plan")
        now = self._now()
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                INSERT INTO runs(
                    run_id, mode, plan_json, budgets_json, fingerprints_json,
                    base_release_id, status, started_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    mode,
                    _json(plan),
                    _json(budgets),
                    _json(fingerprints),
                    base_release_id,
                    status,
                    now if status == "running" else None,
                    now,
                ),
            )

    def create_successor_run(
        self,
        run_id: str,
        *,
        predecessor_run_id: str,
        reason: str,
        compatibility: Mapping[str, Any],
        mode: str,
        plan: Mapping[str, Any],
        budgets: Mapping[str, Any],
        fingerprints: Mapping[str, Any],
        base_release_id: str | None,
    ) -> tuple[str, bool]:
        """Create or recover one audited incident-remediation successor.

        The compatibility document is the idempotency key. A retry returns the
        same still-interrupted successor instead of creating another lineage.
        The caller must hold the single-network-run lock.
        """
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason):
            raise ValueError("successor reason must be machine-readable")
        for label, value in (
            ("compatibility", compatibility),
            ("plan", plan),
            ("budgets", budgets),
            ("fingerprints", fingerprints),
        ):
            _validate_public_payload(value, path="successor." + label)
        compatibility_sha256 = _json_sha256(compatibility)
        now = self._now()
        with self.transaction(immediate=True):
            existing = self.connection.execute(
                """
                SELECT rl.successor_run_id, r.status
                FROM run_lineage rl
                JOIN runs r ON r.run_id=rl.successor_run_id
                WHERE rl.compatibility_sha256=?
                """,
                (compatibility_sha256,),
            ).fetchone()
            if existing is not None:
                if existing["status"] not in {"running", "failed"}:
                    raise RuntimeError(
                        "matching successor is no longer interruptible"
                    )
                return str(existing["successor_run_id"]), False

            predecessor = self.connection.execute(
                """
                SELECT run_id, status FROM runs
                WHERE run_id=?
                """,
                (predecessor_run_id,),
            ).fetchone()
            if predecessor is None:
                raise KeyError(
                    "unknown predecessor run: %s" % predecessor_run_id
                )
            if predecessor["status"] != "abandoned":
                raise RuntimeError(
                    "successor requires an explicitly abandoned predecessor"
                )
            latest = self.connection.execute(
                """
                SELECT run_id FROM runs
                ORDER BY created_at DESC, run_id DESC LIMIT 1
                """
            ).fetchone()
            if latest is None or latest["run_id"] != predecessor_run_id:
                raise RuntimeError(
                    "predecessor is not the latest run; refusing ambiguous lineage"
                )
            self.connection.execute(
                """
                INSERT INTO runs(
                    run_id, mode, plan_json, budgets_json, fingerprints_json,
                    base_release_id, status, started_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    run_id,
                    mode,
                    _json(plan),
                    _json(budgets),
                    _json(fingerprints),
                    base_release_id,
                    now,
                    now,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO run_lineage(
                    successor_run_id, predecessor_run_id, reason,
                    compatibility_sha256, compatibility_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    predecessor_run_id,
                    reason,
                    compatibility_sha256,
                    _json(compatibility),
                    now,
                ),
            )
        return run_id, True

    def inherit_completed_task(
        self,
        *,
        successor_task_id: int,
        predecessor_task_id: int,
        predecessor_run_id: str,
        payload: Mapping[str, Any],
        result: Mapping[str, Any],
        network_task_source_sha256: str,
        source_policy: str,
        inherited_request_count: int,
    ) -> bool:
        """Copy one exactly compatible completed task with durable provenance."""
        if source_policy not in {"required", "advisory"}:
            raise ValueError("invalid inherited source policy")
        if inherited_request_count < 0:
            raise ValueError("inherited request count cannot be negative")
        if not re.fullmatch(r"[0-9a-f]{64}", network_task_source_sha256):
            raise ValueError("invalid network-task executable fingerprint")
        _validate_public_payload(payload, path="inherit.payload")
        _validate_public_payload(result, path="inherit.result")
        payload_json = _json(payload)
        result_json = _json(result)
        payload_sha256 = hashlib.sha256(
            payload_json.encode("utf-8")
        ).hexdigest()
        result_sha256 = hashlib.sha256(
            result_json.encode("utf-8")
        ).hexdigest()
        now = self._now()
        with self.transaction(immediate=True):
            successor = self.connection.execute(
                "SELECT * FROM tasks WHERE task_id=?",
                (int(successor_task_id),),
            ).fetchone()
            predecessor = self.connection.execute(
                "SELECT * FROM tasks WHERE task_id=?",
                (int(predecessor_task_id),),
            ).fetchone()
            if successor is None or predecessor is None:
                raise KeyError("successor or predecessor task is unknown")
            lineage = self.connection.execute(
                """
                SELECT compatibility_json FROM run_lineage
                WHERE successor_run_id=? AND predecessor_run_id=?
                """,
                (successor["run_id"], predecessor_run_id),
            ).fetchone()
            if lineage is None:
                raise RuntimeError("task does not belong to recorded lineage")
            compatibility = json.loads(lineage["compatibility_json"])
            if (
                compatibility.get("network_task_source_sha256")
                != network_task_source_sha256
            ):
                raise RuntimeError(
                    "network-task executable fingerprint changed"
                )
            if (
                predecessor["run_id"] != predecessor_run_id
                or predecessor["status"] != "complete"
                or predecessor["result_json"] is None
            ):
                raise RuntimeError(
                    "predecessor task is not a completed result"
                )
            identity = ("stage", "task_key", "library_id")
            if any(
                successor[field] != predecessor[field]
                for field in identity
            ):
                raise RuntimeError("task identity changed across successor")
            if (
                successor["payload_json"] != payload_json
                or predecessor["payload_json"] != payload_json
                or predecessor["result_json"] != result_json
            ):
                raise RuntimeError(
                    "task payload or result changed across successor"
                )

            inherited = self.connection.execute(
                """
                SELECT * FROM task_inheritance
                WHERE successor_task_id=?
                """,
                (int(successor_task_id),),
            ).fetchone()
            if inherited is not None:
                if (
                    successor["status"] != "complete"
                    or successor["attempts"] != 0
                    or successor["result_json"] != result_json
                    or inherited["predecessor_task_id"]
                    != int(predecessor_task_id)
                    or inherited["payload_sha256"] != payload_sha256
                    or inherited["result_sha256"] != result_sha256
                    or inherited["network_task_source_sha256"]
                    != network_task_source_sha256
                    or inherited["source_policy"] != source_policy
                    or inherited["inherited_request_count"]
                    != int(inherited_request_count)
                ):
                    raise RuntimeError(
                        "existing inherited task provenance differs"
                    )
                return False
            if successor["status"] != "pending" or successor["attempts"] != 0:
                raise RuntimeError(
                    "successor task was attempted before inheritance"
                )
            changed = self.connection.execute(
                """
                UPDATE tasks SET status='complete', result_json=?,
                    lease_owner=NULL, lease_expires_at=NULL,
                    error_code=NULL, updated_at=?, finished_at=?
                WHERE task_id=? AND status='pending' AND attempts=0
                """,
                (result_json, now, now, int(successor_task_id)),
            ).rowcount
            if changed != 1:
                raise RuntimeError("successor task changed during inheritance")
            self.connection.execute(
                """
                INSERT INTO task_inheritance(
                    successor_task_id, successor_run_id,
                    predecessor_run_id, predecessor_task_id, stage, task_key,
                    payload_sha256, result_sha256,
                    network_task_source_sha256, source_policy,
                    inherited_request_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(successor_task_id),
                    successor["run_id"],
                    predecessor_run_id,
                    int(predecessor_task_id),
                    successor["stage"],
                    successor["task_key"],
                    payload_sha256,
                    result_sha256,
                    network_task_source_sha256,
                    source_policy,
                    int(inherited_request_count),
                    now,
                ),
            )
        return True

    def _phase8_deferred_scan_task_keys(
        self,
        run_id: str,
        execution_contract: Mapping[str, Any],
    ) -> set[str]:
        """Return the exact effective owner-deferred scan-tail keys.

        Fresh metadata can remove repositories that are no longer public.  A
        completed privacy resume control therefore narrows the immutable
        owner-deferred partition to the certified surviving subset.  Both the
        original deferral and the narrowing control are validated here before
        generic recovery is allowed to touch task state.
        """
        deferral = execution_contract.get("scan_tail_deferral")
        if deferral is None:
            return set()
        try:
            unsigned = dict(deferral)
            contract_sha256 = unsigned.pop("contract_sha256")
            deferred_keys = unsigned["deferred_task_keys"]
            stage = self.connection.execute(
                """
                SELECT status,checkpoint_json FROM stages
                WHERE run_id=? AND stage='phase8_scan_tail_deferral'
                """,
                (run_id,),
            ).fetchone()
            checkpoint = json.loads(
                stage["checkpoint_json"] if stage is not None else "{}"
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "owner-deferred scan-tail certificate is invalid"
            ) from exc
        if (
            unsigned.get("version") != 1
            or unsigned.get("kind")
            != "phase8-owner-scan-tail-deferral"
            or unsigned.get("policy")
            != "quarantine-exact-unresolved-repositories"
            or not isinstance(deferred_keys, list)
            or deferred_keys != sorted(set(deferred_keys))
            or not all(isinstance(key, str) and key for key in deferred_keys)
            or unsigned.get("deferred_scan_task_count") != len(deferred_keys)
            or unsigned.get("deferred_task_keys_sha256")
            != _json_sha256(deferred_keys)
            or _json_sha256(unsigned) != contract_sha256
            or stage is None
            or stage["status"] != "complete"
            or checkpoint.get("deferral_contract_sha256")
            != contract_sha256
            or checkpoint.get("deferred_task_keys_sha256")
            != unsigned.get("deferred_task_keys_sha256")
            or checkpoint.get("new_scan_attempts") != 0
            or checkpoint.get("changed_scan_results") != 0
            or checkpoint.get("other_budget_changes") != 0
        ):
            raise RuntimeError(
                "owner-deferred scan-tail certificate is invalid"
            )
        privacy = execution_contract.get("privacy_resume_control")
        if privacy is None:
            return set(deferred_keys)
        try:
            privacy_unsigned = dict(privacy)
            privacy_contract_sha256 = privacy_unsigned.pop("contract_sha256")
            remaining_keys = privacy_unsigned[
                "remaining_deferred_task_keys"
            ]
            privacy_stage = self.connection.execute(
                """
                SELECT status,checkpoint_json FROM stages
                WHERE run_id=? AND stage='phase8_privacy_resume_control'
                """,
                (run_id,),
            ).fetchone()
            privacy_checkpoint = json.loads(
                privacy_stage["checkpoint_json"]
                if privacy_stage is not None else "{}"
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "owner-deferred privacy certificate is invalid"
            ) from exc
        remaining_set = set(remaining_keys) if isinstance(
            remaining_keys, list
        ) else set()
        deferred_set = set(deferred_keys)
        privacy_count_fields = (
            "prior_scan_task_count",
            "current_scan_task_count",
            "current_completed_scan_task_count",
            "current_deferred_scan_task_count",
            "purged_scan_task_count",
            "purged_completed_scan_task_count",
            "purged_deferred_scan_task_count",
        )
        if (
            privacy_unsigned.get("version") != 1
            or privacy_unsigned.get("kind")
            != "phase8-privacy-resume-control"
            or privacy_unsigned.get("policy")
            != "purge-nonpublic-and-pin-surviving-scan-evidence"
            or not isinstance(remaining_keys, list)
            or remaining_keys != sorted(remaining_set)
            or not all(
                isinstance(key, str) and re.fullmatch(r"[0-9a-f]{64}", key)
                for key in remaining_keys
            )
            or not remaining_set.issubset(deferred_set)
            or any(
                not isinstance(privacy_unsigned.get(field), int)
                or isinstance(privacy_unsigned[field], bool)
                or privacy_unsigned[field] < 0
                for field in privacy_count_fields
            )
            or privacy_unsigned.get("remaining_deferred_task_keys_sha256")
            != _json_sha256(remaining_keys)
            or privacy_unsigned.get("current_deferred_scan_task_count")
            != len(remaining_keys)
            or privacy_unsigned.get("purged_deferred_scan_task_count")
            != len(deferred_set - remaining_set)
            or privacy_unsigned.get("prior_scan_task_count")
            != unsigned.get("task_universe_count")
            or privacy_unsigned.get("prior_scan_task_count")
            != privacy_unsigned.get("current_scan_task_count")
            + privacy_unsigned.get("purged_scan_task_count")
            or privacy_unsigned.get("purged_scan_task_count")
            != privacy_unsigned.get("purged_completed_scan_task_count")
            + privacy_unsigned.get("purged_deferred_scan_task_count")
            or privacy_unsigned.get("current_scan_task_count")
            != privacy_unsigned.get("current_completed_scan_task_count")
            + privacy_unsigned.get("current_deferred_scan_task_count")
            or privacy_unsigned.get("new_scan_attempts") != 0
            or privacy_unsigned.get("changed_scan_results") != 0
            or privacy_unsigned.get("changed_citation_cache_entries") != 0
            or privacy_unsigned.get("other_budget_changes") != 0
            or _json_sha256(privacy_unsigned) != privacy_contract_sha256
            or privacy_stage is None
            or privacy_stage["status"] != "complete"
            or privacy_checkpoint.get("control") != privacy
        ):
            raise RuntimeError(
                "owner-deferred privacy certificate is invalid"
            )
        post_refresh = execution_contract.get(
            "post_refresh_privacy_control"
        )
        if post_refresh is None:
            return remaining_set
        try:
            post_unsigned = dict(post_refresh)
            post_contract_sha256 = post_unsigned.pop("contract_sha256")
            post_remaining = post_unsigned["remaining_deferred_task_keys"]
            post_stage = self.connection.execute(
                """
                SELECT status,checkpoint_json FROM stages
                WHERE run_id=?
                  AND stage='phase8_post_refresh_privacy_control'
                """,
                (run_id,),
            ).fetchone()
            post_checkpoint = json.loads(
                post_stage["checkpoint_json"]
                if post_stage is not None else "{}"
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "owner-deferred post-refresh privacy certificate is invalid"
            ) from exc
        post_set = set(post_remaining) if isinstance(
            post_remaining, list
        ) else set()
        post_head_pins = post_unsigned.get("deferred_scan_head_pins")
        raw_actual_counts = dict(self.connection.execute(
            """
            SELECT status,COUNT(*) FROM tasks
            WHERE run_id=? AND stage='scan' GROUP BY status
            """,
            (run_id,),
        ).fetchall())
        actual_counts = {
            "complete": int(raw_actual_counts.get("complete", 0)),
            "failed": int(raw_actual_counts.get("failed", 0)),
        }
        if (
            post_unsigned.get("version") != 2
            or post_unsigned.get("kind")
            != "phase8-post-refresh-privacy-control"
            or post_unsigned.get("policy")
            != "adopt-one-additional-nonpublic-purge-and-pin-surviving-evidence"
            or post_unsigned.get("privacy_resume_contract_sha256")
            != privacy_contract_sha256
            or not isinstance(post_remaining, list)
            or post_remaining != sorted(post_set)
            or post_set != remaining_set
            or post_unsigned.get("remaining_deferred_task_keys_sha256")
            != _json_sha256(post_remaining)
            or not isinstance(
                post_unsigned.get("deferred_scan_head_pin_count"), int
            )
            or isinstance(
                post_unsigned.get("deferred_scan_head_pin_count"), bool
            )
            or post_unsigned["deferred_scan_head_pin_count"] < 0
            or not isinstance(post_head_pins, list)
            or len(post_head_pins)
            != post_unsigned["deferred_scan_head_pin_count"]
            or post_head_pins != sorted(
                post_head_pins,
                key=lambda item: item.get("task_key", "")
                if isinstance(item, Mapping) else "",
            )
            or post_unsigned.get("deferred_scan_head_pins_sha256")
            != _json_sha256(post_head_pins)
            or post_unsigned.get("prior_scan_task_count")
            != privacy_unsigned.get("current_scan_task_count")
            or post_unsigned.get("prior_completed_scan_task_count")
            != privacy_unsigned.get("current_completed_scan_task_count")
            or post_unsigned.get("additional_purged_scan_task_count") != 1
            or post_unsigned.get(
                "additional_purged_completed_scan_task_count"
            ) != 1
            or post_unsigned.get(
                "additional_purged_deferred_scan_task_count"
            ) != 0
            or post_unsigned.get("current_scan_task_count")
            != post_unsigned.get("prior_scan_task_count") - 1
            or post_unsigned.get("current_completed_scan_task_count")
            != post_unsigned.get("prior_completed_scan_task_count") - 1
            or post_unsigned.get("current_deferred_scan_task_count")
            != len(post_remaining)
            or set(raw_actual_counts) - {"complete", "failed"}
            or (
                execution_contract.get(
                    "final_visibility_privacy_control"
                ) is None
                and actual_counts != {
                    "complete": post_unsigned.get(
                        "current_completed_scan_task_count"
                    ),
                    "failed": post_unsigned.get(
                        "current_deferred_scan_task_count"
                    ),
                }
            )
            or post_unsigned.get("new_scan_attempts") != 0
            or post_unsigned.get("changed_surviving_scan_results") != 0
            or post_unsigned.get("changed_citation_cache_entries") != 0
            or post_unsigned.get("other_budget_changes") != 0
            or _json_sha256(post_unsigned) != post_contract_sha256
            or post_stage is None
            or post_stage["status"] != "complete"
            or post_checkpoint.get("control") != post_refresh
        ):
            raise RuntimeError(
                "owner-deferred post-refresh privacy certificate is invalid"
            )
        final_visibility = execution_contract.get(
            "final_visibility_privacy_control"
        )
        if final_visibility is None:
            return post_set
        try:
            final_unsigned = dict(final_visibility)
            final_contract_sha256 = final_unsigned.pop("contract_sha256")
            final_remaining = final_unsigned[
                "remaining_deferred_task_keys"
            ]
            final_stage = self.connection.execute(
                """
                SELECT status,checkpoint_json FROM stages
                WHERE run_id=?
                  AND stage='phase8_final_visibility_privacy_control'
                """,
                (run_id,),
            ).fetchone()
            final_checkpoint = json.loads(
                final_stage["checkpoint_json"]
                if final_stage is not None else "{}"
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "owner-deferred final-visibility privacy certificate is "
                "invalid"
            ) from exc
        final_set = set(final_remaining) if isinstance(
            final_remaining, list
        ) else set()
        final_actual_raw = dict(self.connection.execute(
            """
            SELECT status,COUNT(*) FROM tasks
            WHERE run_id=? AND stage='scan' GROUP BY status
            """,
            (run_id,),
        ).fetchall())
        if (
            final_unsigned.get("version") != 1
            or final_unsigned.get("kind")
            != "phase8-final-visibility-privacy-control"
            or final_unsigned.get("policy")
            != "purge-one-final-missing-node-and-resume-compatible-epoch"
            or final_unsigned.get("post_refresh_privacy_contract_sha256")
            != post_contract_sha256
            or not isinstance(final_remaining, list)
            or final_remaining != sorted(final_set)
            or final_set != post_set
            or final_unsigned.get("remaining_deferred_task_keys_sha256")
            != _json_sha256(final_remaining)
            or final_unsigned.get("prior_scan_task_count")
            != post_unsigned.get("current_scan_task_count")
            or final_unsigned.get("prior_completed_scan_task_count")
            != post_unsigned.get("current_completed_scan_task_count")
            or final_unsigned.get("purged_scan_task_count") != 1
            or final_unsigned.get("purged_completed_scan_task_count") != 1
            or final_unsigned.get("purged_deferred_scan_task_count") != 0
            or final_unsigned.get("current_scan_task_count")
            != final_unsigned.get("prior_scan_task_count") - 1
            or final_unsigned.get("current_completed_scan_task_count")
            != final_unsigned.get("prior_completed_scan_task_count") - 1
            or final_unsigned.get("current_deferred_scan_task_count")
            != len(final_remaining)
            or set(final_actual_raw) - {"complete", "failed"}
            or {
                "complete": int(final_actual_raw.get("complete", 0)),
                "failed": int(final_actual_raw.get("failed", 0)),
            } != {
                "complete": final_unsigned.get(
                    "current_completed_scan_task_count"
                ),
                "failed": final_unsigned.get(
                    "current_deferred_scan_task_count"
                ),
            }
            or final_unsigned.get("new_metadata_request_count") != 0
            or final_unsigned.get("new_final_visibility_request_count") != 0
            or final_unsigned.get("new_scan_attempts") != 0
            or final_unsigned.get("changed_surviving_scan_results") != 0
            or final_unsigned.get("changed_citation_cache_entries") != 0
            or final_unsigned.get("other_budget_changes") != 0
            or _json_sha256(final_unsigned) != final_contract_sha256
            or final_stage is None
            or final_stage["status"] != "complete"
            or final_checkpoint.get("control") != final_visibility
        ):
            raise RuntimeError(
                "owner-deferred final-visibility privacy certificate is "
                "invalid"
            )
        return final_set

    def resume_compatible_run(
        self,
        *,
        mode: str,
        budgets: Mapping[str, Any] | None = None,
        fingerprints: Mapping[str, Any] | None = None,
        base_release_id: str | None = None,
        execution_contract: Mapping[str, Any] | None = None,
    ) -> str | None:
        """Return the interrupted run ID when its execution contract matches.

        The latest ``running`` or ``failed`` run is resumable.  A later complete
        or explicitly abandoned run closes that recovery window.  The caller
        must hold the single-network-run lock before invoking this method, so a
        still-live coordinator cannot be mistaken for a crash.

        An interrupted run with different mode, hard budgets, fingerprints, or
        base release is refused rather than mixing work from incompatible
        execution contracts.
        """
        budgets = budgets or {}
        fingerprints = fingerprints or {}
        execution_contract = execution_contract or {}
        _validate_public_payload(budgets, path="run.budgets")
        _validate_public_payload(fingerprints, path="run.fingerprints")
        _validate_public_payload(
            execution_contract, path="run.execution_contract"
        )
        row = self.connection.execute(
            """
            SELECT run_id, mode, plan_json, budgets_json, fingerprints_json,
                   base_release_id, status
            FROM runs
            ORDER BY created_at DESC, run_id DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None or row["status"] not in {"running", "failed"}:
            return None
        compatible = (
            row["mode"] == mode
            and row["budgets_json"] == _json(budgets)
            and row["fingerprints_json"] == _json(fingerprints)
            and row["base_release_id"] == base_release_id
            and (
                (
                    json.loads(row["plan_json"] or "{}")
                    .get("execution_contract")
                    or {}
                )
                == execution_contract
            )
        )
        if not compatible:
            raise RuntimeError(
                "incompatible interrupted run %s must be explicitly resolved"
                % row["run_id"]
            )
        deferred_scan_task_keys = self._phase8_deferred_scan_task_keys(
            str(row["run_id"]), execution_contract
        )
        with self.transaction(immediate=True):
            now = self._now()
            self.connection.execute(
                """
                UPDATE runs SET status='running', finished_at=NULL,
                    checkpoint_at=?
                WHERE run_id=?
                """,
                (now, row["run_id"]),
            )
            self.connection.execute(
                """
                UPDATE scan_attempts SET status='interrupted', retryable=1,
                    error_code=COALESCE(
                        error_code, 'coordinator_interrupted'
                    ),
                    usage_complete=0, finished_at=?
                WHERE run_id=? AND status='running'
                """,
                (now, row["run_id"]),
            )
            # Holding the recovered run lock proves that any prior coordinator
            # is gone.  Requeue its unfinished work immediately instead of
            # waiting out repository-sized leases.  Exhausted tasks stay failed
            # and continue to block publication.
            scan_tasks = self.connection.execute(
                """
                SELECT * FROM tasks
                WHERE run_id=? AND stage='scan'
                  AND status IN ('pending', 'running', 'failed')
                ORDER BY task_id
                """,
                (row["run_id"],),
            ).fetchall()
            if deferred_scan_task_keys and {
                str(task["task_key"]) for task in scan_tasks
            } != deferred_scan_task_keys:
                raise RuntimeError(
                    "owner-deferred scan-tail task partition changed"
                )
            for task in scan_tasks:
                if str(task["task_key"]) in deferred_scan_task_keys:
                    status = "failed"
                    error_code = (
                        task["error_code"] or "owner_deferred_scan_tail"
                    )
                else:
                    status, error_code = (
                        self._scan_task_recovery_disposition(
                            task, allow_unknown_retry=True
                        )
                    )
                self.connection.execute(
                    """
                    UPDATE tasks SET status=?, lease_owner=NULL,
                        lease_expires_at=NULL, error_code=?,
                        finished_at=?, updated_at=?
                    WHERE task_id=?
                    """,
                    (
                        status,
                        error_code,
                        now if status == "failed" else None,
                        now,
                        task["task_id"],
                    ),
                )
            self.connection.execute(
                """
                UPDATE tasks SET
                    status=CASE
                        WHEN attempts >= max_attempts THEN 'failed'
                        ELSE 'pending'
                    END,
                    lease_owner=NULL,
                    lease_expires_at=NULL,
                    error_code=CASE
                        WHEN attempts >= max_attempts
                        THEN COALESCE(error_code, 'resume_max_attempts')
                        ELSE error_code
                    END,
                    finished_at=CASE
                        WHEN attempts >= max_attempts THEN COALESCE(finished_at, ?)
                        ELSE NULL
                    END,
                    updated_at=?
                WHERE run_id=? AND stage!='scan'
                  AND status IN ('running', 'failed')
                """,
                (now, now, row["run_id"]),
            )
        return str(row["run_id"])

    def _scan_task_recovery_disposition(
        self,
        task: Mapping[str, Any],
        *,
        allow_unknown_retry: bool = False,
    ) -> tuple[str, str | None]:
        """Return one fail-closed restart decision from the attempt ledger."""
        attempts = int(task["attempts"])
        if attempts == 0:
            return "pending", task["error_code"]
        attempt_summary = self.connection.execute(
            """
            SELECT COUNT(*) AS attempt_count,
                   COALESCE(SUM(
                       CASE WHEN usage_complete=1 THEN 0 ELSE 1 END
                   ), 0) AS incomplete_count
            FROM scan_attempts
            WHERE task_id=?
            """,
            (str(task["task_id"]),),
        ).fetchone()
        attempt = self.connection.execute(
            """
            SELECT status, retryable, error_code, usage_complete
            FROM scan_attempts
            WHERE task_id=? AND attempt=?
            """,
            (str(task["task_id"]), attempts),
        ).fetchone()
        if attempt is None or int(attempt_summary["attempt_count"]) != attempts:
            return "failed", "resume_scan_usage_unknown"
        reviewed_retry = self._phase8_reviewed_scan_retry(task)
        if reviewed_retry is not None:
            if attempts >= int(task["max_attempts"]):
                return "failed", "resume_max_attempts"
            return "pending", reviewed_retry
        if int(attempt_summary["incomplete_count"]) != 0:
            if (
                allow_unknown_retry
                and attempt["status"] == "interrupted"
                and attempt["retryable"] == 1
                and attempts < int(task["max_attempts"])
            ):
                return (
                    "pending",
                    attempt["error_code"] or "resume_scan_usage_unknown",
                )
            return "failed", "resume_scan_usage_unknown"
        typed_error = attempt["error_code"] or task["error_code"]
        if (
            attempt["status"] == "failed"
            and attempt["retryable"] == 0
        ):
            return (
                "failed",
                typed_error or "resume_nonretryable_scan_failure",
            )
        if attempts >= int(task["max_attempts"]):
            return "failed", typed_error or "resume_max_attempts"
        return "pending", typed_error

    def _phase8_reviewed_scan_retry(
        self,
        task: Mapping[str, Any],
    ) -> str | None:
        """Revalidate a durable issue-lane retry across repeated resumes."""
        marker = str(task["error_code"] or "")
        if not marker.startswith("issue_retry:"):
            return None
        task_id = int(task["task_id"])
        attempts = int(task["attempts"])
        if marker == "issue_retry:approved_buildozer_exclusion":
            row = self.connection.execute(
                """
                SELECT status,checkpoint_json FROM stages
                WHERE run_id=? AND stage='phase8_buildozer_issue_retry'
                """,
                (task["run_id"],),
            ).fetchone()
            try:
                checkpoint = json.loads(
                    row["checkpoint_json"] if row is not None else "{}"
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                return None
            if (
                row is not None
                and row["status"] == "complete"
                and checkpoint.get("task_id") == task_id
                and self._phase8_reviewed_retry_task_key(
                    task, checkpoint.get("task_key")
                )
                and checkpoint.get("prior_attempts") == attempts
                and checkpoint.get("reset_task_count") == 1
                and checkpoint.get("other_budget_changes") == 0
            ):
                return marker
            return None
        if marker == "issue_retry:audited_scanner_source_migration":
            row = self.connection.execute(
                """
                SELECT status,checkpoint_json FROM stages
                WHERE run_id=?
                  AND stage='phase8_scanner_source_issue_retry'
                """,
                (task["run_id"],),
            ).fetchone()
            try:
                checkpoint = json.loads(
                    row["checkpoint_json"] if row is not None else "{}"
                )
                selected = checkpoint["selected_tasks"]
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                return None
            if (
                row is None
                or row["status"] != "complete"
                or checkpoint.get("version") != 1
                or checkpoint.get("selection_sha256")
                != _json_sha256(selected)
                or checkpoint.get("reset_task_count") != len(selected)
                or checkpoint.get("reset_task_count") != 4
                or checkpoint.get("other_budget_changes") != 0
                or not isinstance(
                    checkpoint.get("task_universe_count"), int
                )
                or isinstance(
                    checkpoint.get("task_universe_count"), bool
                )
                or checkpoint["task_universe_count"] < len(selected)
                or not isinstance(
                    checkpoint.get("scanner_migration_contract_sha256"),
                    str,
                )
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    checkpoint["scanner_migration_contract_sha256"],
                )
            ):
                return None
            matches = [
                item for item in selected
                if (
                    item.get("task_id") == task_id
                    and item.get("task_key") == task["task_key"]
                    and item.get("prior_attempts") == attempts
                    and item.get("target_max_attempts")
                    == int(task["max_attempts"])
                    and item.get("policy")
                    == "audited_scanner_source_migration"
                )
            ]
            return marker if len(matches) == 1 else None
        if marker not in {
            "issue_retry:bounded_transient_retry",
            "issue_retry:exact_runtime_reclassification",
        }:
            return None
        row = self.connection.execute(
            """
            SELECT status,checkpoint_json FROM stages
            WHERE run_id=? AND stage='phase8_issue_retry'
            """,
            (task["run_id"],),
        ).fetchone()
        try:
            checkpoint = json.loads(
                row["checkpoint_json"] if row is not None else "{}"
            )
            selected = checkpoint["selected_tasks"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None
        if (
            row is None
            or row["status"] != "complete"
            or checkpoint.get("selection_sha256") != _json_sha256(selected)
            or checkpoint.get("reset_task_count") != len(selected)
            or checkpoint.get("other_budget_changes") != 0
        ):
            return None
        policy = marker.split(":", 1)[1]
        matches = [
            item for item in selected
            if (
                item.get("task_id") == task_id
                and self._phase8_reviewed_retry_task_key(
                    task, item.get("task_key")
                )
                and item.get("attempts") == attempts
                and item.get("policy") == policy
            )
        ]
        return marker if len(matches) == 1 else None

    def _phase8_reviewed_retry_task_key(
        self,
        task: Mapping[str, Any],
        certified_task_key: Any,
    ) -> bool:
        """Accept an old retry key only through the audited all-task re-key."""
        if certified_task_key == task["task_key"]:
            return True
        if not isinstance(certified_task_key, str):
            return False
        attempt = self.connection.execute(
            """
            SELECT task_key FROM scan_attempts
            WHERE task_id=? AND attempt=?
            """,
            (str(task["task_id"]), int(task["attempts"])),
        ).fetchone()
        run = self.connection.execute(
            "SELECT plan_json FROM runs WHERE run_id=?",
            (task["run_id"],),
        ).fetchone()
        stage = self.connection.execute(
            """
            SELECT status,checkpoint_json FROM stages
            WHERE run_id=? AND stage='phase8_scanner_source_migration'
            """,
            (task["run_id"],),
        ).fetchone()
        try:
            execution = json.loads(run["plan_json"])["execution_contract"]
            migration = execution["scanner_source_migration"]
            checkpoint = json.loads(stage["checkpoint_json"])
            task_universe = int(migration["task_universe_count"])
            migrated_keys = int(migration["migrated_scan_task_key_count"])
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return False
        counts = self.connection.execute(
            """
            SELECT COUNT(*) AS task_count,
                   COUNT(DISTINCT task_key) AS distinct_key_count
            FROM tasks WHERE run_id=? AND stage='scan'
            """,
            (task["run_id"],),
        ).fetchone()
        contract_sha256 = migration.get("contract_sha256")
        unsigned = {
            key: value for key, value in migration.items()
            if key != "contract_sha256"
        }
        return bool(
            attempt is not None
            and run is not None
            and stage is not None
            and stage["status"] == "complete"
            and attempt["task_key"] == certified_task_key
            and checkpoint.get("migration") == migration
            and isinstance(contract_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", contract_sha256)
            and contract_sha256 == _json_sha256(unsigned)
            and task_universe > 0
            and migrated_keys == task_universe
            and int(counts["task_count"]) == task_universe
            and int(counts["distinct_key_count"]) == task_universe
        )

    def checkpoint_run(
        self,
        run_id: str,
        *,
        stage: str | None = None,
        checkpoint: Mapping[str, Any] | None = None,
    ) -> None:
        _validate_public_payload(checkpoint or {}, path="checkpoint")
        now = self._now()
        with self.transaction(immediate=True):
            changed = self.connection.execute(
                "UPDATE runs SET checkpoint_at=? WHERE run_id=?", (now, run_id)
            ).rowcount
            if changed != 1:
                raise KeyError(f"unknown run: {run_id}")
            if stage is not None:
                self.connection.execute(
                    """
                    INSERT INTO stages(
                        run_id, stage, status, checkpoint_json, updated_at
                    ) VALUES (?, ?, 'running', ?, ?)
                    ON CONFLICT(run_id, stage) DO UPDATE SET
                        checkpoint_json=excluded.checkpoint_json,
                        updated_at=excluded.updated_at
                    """,
                    (run_id, stage, _json(checkpoint), now),
                )

    def abandon_run(self, run_id: str, *, reason: str) -> None:
        """Explicitly close an interrupted run so a new contract may start."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason):
            raise ValueError("abandon reason must be machine-readable")
        now = self._now()
        with self.transaction(immediate=True):
            row = self.connection.execute(
                "SELECT status FROM runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown run: {run_id}")
            if row["status"] not in {"running", "failed"}:
                raise RuntimeError("only interrupted runs can be abandoned")
            self.connection.execute(
                """
                UPDATE scan_attempts SET status='interrupted', retryable=0,
                    error_code=?, usage_complete=0, finished_at=?
                WHERE run_id=? AND status='running'
                """,
                ("run_abandoned:" + reason, now, run_id),
            )
            self.connection.execute(
                """
                UPDATE tasks SET status='failed', lease_owner=NULL,
                    lease_expires_at=NULL, error_code=?, updated_at=?,
                    finished_at=?
                WHERE run_id=? AND status!='complete'
                """,
                ("run_abandoned:" + reason, now, now, run_id),
            )
            self.connection.execute(
                """
                UPDATE stages SET status='failed', finished_at=?, updated_at=?
                WHERE run_id=? AND status IN ('pending', 'running')
                """,
                (now, now, run_id),
            )
            self.connection.execute(
                """
                UPDATE runs SET status='abandoned', finished_at=?,
                    checkpoint_at=?
                WHERE run_id=?
                """,
                (now, now, run_id),
            )

    def reset_failed_tasks(self, run_id: str, *, reason: str) -> int:
        """Reviewed retry reset for an otherwise compatible interrupted run."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason):
            raise ValueError("retry reason must be machine-readable")
        now = self._now()
        with self.transaction(immediate=True):
            row = self.connection.execute(
                "SELECT status FROM runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown run: {run_id}")
            if row["status"] not in {"running", "failed"}:
                raise RuntimeError("only interrupted runs can be retried")
            changed = self.connection.execute(
                """
                UPDATE tasks SET status='pending',
                    max_attempts=CASE
                        WHEN max_attempts <= attempts THEN attempts + 1
                        ELSE max_attempts
                    END,
                    lease_owner=NULL, lease_expires_at=NULL,
                    available_at=0, error_code=?, updated_at=?,
                    finished_at=NULL
                WHERE run_id=? AND status='failed'
                """,
                ("reviewed_retry:" + reason, now, run_id),
            ).rowcount
            self.connection.execute(
                """
                UPDATE runs SET status='running', finished_at=NULL,
                    checkpoint_at=? WHERE run_id=?
                """,
                (now, run_id),
            )
            return changed

    def update_stage(
        self,
        run_id: str,
        stage: str,
        *,
        status: str,
        counters: Mapping[str, Any] | None = None,
        metrics: Mapping[str, Any] | None = None,
        checkpoint: Mapping[str, Any] | None = None,
    ) -> None:
        for label, payload in (
            ("counters", counters or {}),
            ("metrics", metrics or {}),
            ("checkpoint", checkpoint or {}),
        ):
            _validate_public_payload(payload, path=f"stage.{label}")
        now = self._now()
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                INSERT INTO stages(
                    run_id, stage, status, counters_json, metrics_json,
                    checkpoint_json, started_at, finished_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, stage) DO UPDATE SET
                    status=excluded.status,
                    counters_json=excluded.counters_json,
                    metrics_json=excluded.metrics_json,
                    checkpoint_json=excluded.checkpoint_json,
                    started_at=COALESCE(stages.started_at, excluded.started_at),
                    finished_at=excluded.finished_at,
                    updated_at=excluded.updated_at
                """,
                (
                    run_id,
                    stage,
                    status,
                    _json(counters),
                    _json(metrics),
                    _json(checkpoint),
                    now if status == "running" else None,
                    now if status in {"complete", "failed"} else None,
                    now,
                ),
            )
            self.connection.execute(
                "UPDATE runs SET checkpoint_at=? WHERE run_id=?", (now, run_id)
            )

    def _assert_run_publishable(self, run_id: str) -> None:
        run = self.connection.execute(
            "SELECT mode, plan_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        if run is None:
            raise KeyError(f"unknown run: {run_id}")
        try:
            plan = json.loads(run["plan_json"] or "{}")
            execution = plan.get("execution_contract") or {}
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("run plan is malformed") from exc
        unresolved_rows = self.connection.execute(
            """
            SELECT task_id,task_key,status FROM tasks
            WHERE run_id=? AND status != 'complete'
            ORDER BY task_key
            """,
            (run_id,),
        ).fetchall()
        deferred_task_ids: set[int] = set()
        if unresolved_rows:
            try:
                deferred_keys = sorted(
                    self._phase8_deferred_scan_task_keys(run_id, execution)
                )
            except RuntimeError as exc:
                raise RuntimeError(
                    "owner-deferred scan-tail certificate is invalid"
                ) from exc
            actual_keys = [str(row["task_key"]) for row in unresolved_rows]
            if (
                actual_keys != deferred_keys
                or any(row["status"] != "failed" for row in unresolved_rows)
            ):
                raise RuntimeError(
                    "owner-deferred scan-tail certificate is invalid"
                )
            deferred_task_ids = {
                int(row["task_id"]) for row in unresolved_rows
            }

        invalid_notebook_tasks = {
            int(row["task_id"])
            for row in self.connection.execute(
                """
                SELECT DISTINCT t.task_id
                FROM tasks t JOIN scan_attempts sa
                  ON sa.task_id=CAST(t.task_id AS TEXT)
                WHERE t.run_id=? AND t.stage='scan'
                  AND sa.error_code='invalid_notebook'
                """,
                (run_id,),
            )
        }
        invalid_notebook_tasks -= deferred_task_ids
        if invalid_notebook_tasks:
            stage = self.connection.execute(
                """
                SELECT status,checkpoint_json FROM stages
                WHERE run_id=? AND stage='phase8_notebook_issue_lane'
                """,
                (run_id,),
            ).fetchone()
            try:
                checkpoint = json.loads(
                    stage["checkpoint_json"] if stage is not None else "{}"
                )
                proof = dict(checkpoint["proof"])
                proof_sha256 = proof.pop("contract_sha256")
                successes = checkpoint["successful_tasks"]
                success_ids = {
                    int(item["task_id"]) for item in successes
                }
                proof_ids = {
                    int(item["task_id"])
                    for item in proof["proofs"]
                    if item.get("retention_token_hits") == []
                }
            except (
                KeyError, TypeError, ValueError, json.JSONDecodeError
            ) as exc:
                raise RuntimeError(
                    "malformed-notebook recovery certificate is invalid"
                ) from exc
            if (
                stage is None
                or stage["status"] != "complete"
                or checkpoint.get("version") != 1
                or proof.get("version") != 1
                or proof.get("kind")
                != "phase8-exact-malformed-notebook-negative-proof"
                or _json_sha256(proof) != proof_sha256
                or _json_sha256(successes)
                != checkpoint.get("successful_tasks_sha256")
                or success_ids != invalid_notebook_tasks
                or proof_ids != invalid_notebook_tasks
                or checkpoint.get("completed_checkpoint_replayed") != 0
                or checkpoint.get("other_budget_changes") != 0
            ):
                raise RuntimeError(
                    "malformed-notebook recovery is not certified"
                )
            for success in successes:
                task = self.connection.execute(
                    "SELECT status,result_json FROM tasks WHERE task_id=?",
                    (int(success["task_id"]),),
                ).fetchone()
                if (
                    task is None
                    or task["status"] != "complete"
                    or task["result_json"] is None
                    or hashlib.sha256(
                        task["result_json"].encode("utf-8")
                    ).hexdigest() != success.get("result_sha256")
                ):
                    raise RuntimeError(
                        "malformed-notebook recovered result changed"
                    )

        blocked_lfs_tasks = {
            int(row["task_id"])
            for row in self.connection.execute(
                """
                SELECT DISTINCT t.task_id
                FROM tasks t JOIN scan_attempts sa
                  ON sa.task_id=CAST(t.task_id AS TEXT)
                WHERE t.run_id=? AND t.stage='scan'
                  AND sa.error_detail LIKE
                    'could not inspect detector-relevant LFS path:%(errno=1)'
                """,
                (run_id,),
            )
        }
        blocked_lfs_tasks -= deferred_task_ids
        if blocked_lfs_tasks:
            stage = self.connection.execute(
                """
                SELECT status,checkpoint_json FROM stages
                WHERE run_id=? AND stage='phase8_lfs_inspection_issue_lane'
                """,
                (run_id,),
            ).fetchone()
            try:
                checkpoint = json.loads(
                    stage["checkpoint_json"] if stage is not None else "{}"
                )
                proof = dict(checkpoint["proof"])
                proof_sha256 = proof.pop("contract_sha256")
                successes = checkpoint["successful_tasks"]
                success_ids = {
                    int(item["task_id"]) for item in successes
                }
                proof_ids = {
                    int(item["task_id"]) for item in proof["proofs"]
                    if item.get("lfs_pointer") is False
                    and item.get("read_authority") == "exact-local-git-blob"
                }
            except (
                KeyError, TypeError, ValueError, json.JSONDecodeError
            ) as exc:
                raise RuntimeError(
                    "blocked LFS-inspection recovery certificate is invalid"
                ) from exc
            if (
                stage is None
                or stage["status"] != "complete"
                or checkpoint.get("version") != 1
                or proof.get("version") != 1
                or proof.get("kind")
                != "phase8-exact-blocked-lfs-inspection-proof"
                or _json_sha256(proof) != proof_sha256
                or _json_sha256(successes)
                != checkpoint.get("successful_tasks_sha256")
                or success_ids != blocked_lfs_tasks
                or proof_ids != blocked_lfs_tasks
                or checkpoint.get("completed_checkpoint_replayed") != 0
                or checkpoint.get("other_budget_changes") != 0
            ):
                raise RuntimeError(
                    "blocked LFS-inspection recovery is not certified"
                )
            for success in successes:
                task = self.connection.execute(
                    "SELECT status,result_json FROM tasks WHERE task_id=?",
                    (int(success["task_id"]),),
                ).fetchone()
                if (
                    task is None
                    or task["status"] != "complete"
                    or task["result_json"] is None
                    or hashlib.sha256(
                        task["result_json"].encode("utf-8")
                    ).hexdigest() != success.get("result_sha256")
                ):
                    raise RuntimeError(
                        "blocked LFS-inspection recovered result changed"
                    )

        buildozer_proof = execution.get("filter_extension")
        if buildozer_proof is not None:
            try:
                proof = dict(buildozer_proof)
                proof_sha256 = proof.pop("contract_sha256")
                incident_task_id = int(proof["incident_task_id"])
                incident_prior_attempts = int(
                    proof["incident_prior_attempts"]
                )
                stage = self.connection.execute(
                    """
                    SELECT status,checkpoint_json FROM stages
                    WHERE run_id=? AND stage='phase8_buildozer_issue_retry'
                    """,
                    (run_id,),
                ).fetchone()
                checkpoint = json.loads(
                    stage["checkpoint_json"] if stage is not None else "{}"
                )
            except (
                KeyError, TypeError, ValueError, json.JSONDecodeError
            ) as exc:
                raise RuntimeError(
                    "buildozer recovery certificate is invalid"
                ) from exc
            task = self.connection.execute(
                """
                SELECT status,attempts,result_json FROM tasks
                WHERE run_id=? AND task_id=? AND stage='scan'
                """,
                (run_id, incident_task_id),
            ).fetchone()
            buildozer_result_paths = int(self.connection.execute(
                """
                SELECT COUNT(*) FROM tasks
                WHERE run_id=? AND stage='scan' AND status='complete'
                  AND lower(result_json) LIKE '%.buildozer/%'
                """,
                (run_id,),
            ).fetchone()[0])
            if (
                proof.get("version") != 1
                or proof.get("kind")
                != "phase8-exact-buildozer-generated-output-filter-extension"
                or proof.get("directory_segment") != ".buildozer"
                or proof.get("completed_results_with_buildozer_evidence") != 0
                or _json_sha256(proof) != proof_sha256
                or stage is None
                or stage["status"] != "complete"
                or checkpoint.get("task_id") != incident_task_id
                or checkpoint.get("filter_extension_contract_sha256")
                != proof_sha256
                or checkpoint.get("reset_task_count") != 1
                or checkpoint.get("other_budget_changes") != 0
                or task is None
                or task["status"] != "complete"
                or int(task["attempts"]) <= incident_prior_attempts
                or task["result_json"] is None
                or buildozer_result_paths != 0
            ):
                raise RuntimeError("buildozer recovery is not certified")

        discovery_tasks = []
        for row in self.connection.execute(
            """
            SELECT task_id, task_key, library_id, payload_json, result_json
            FROM tasks
            WHERE run_id=? AND stage='discovery-query'
              AND status='complete'
            ORDER BY task_id
            """,
            (run_id,),
        ):
            try:
                payload = json.loads(row["payload_json"])
                result = json.loads(row["result_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    "run has malformed discovery task documents"
                ) from exc
            if result.get("superseded") is True:
                continue
            discovery_tasks.append((row, payload, result))

        if not discovery_tasks:
            return
        selected = {
            str(item)
            for item in execution.get("selected_library_ids") or ()
        }
        github_libraries = {
            str(payload.get("library_id"))
            for _row, payload, _result in discovery_tasks
            if payload.get("source") == "github-code-search"
        }
        required_source = (
            "github-code-search"
            if run["mode"] == "reconcile"
            or (selected and github_libraries == selected)
            else "sourcegraph"
        )

        violations = []
        for row, payload, result in discovery_tasks:
            if payload.get("source") != required_source:
                continue
            try:
                _validate_public_payload(
                    result, path="publication.discovery_result"
                )
            except ValueError as exc:
                violations.append(
                    "%s is not public-only: %s"
                    % (row["task_key"], exc)
                )
                continue
            certificate = result.get("certificate")
            if (
                result.get("version") != 1
                or result.get("kind") != "discovery-query"
                or not isinstance(certificate, Mapping)
            ):
                violations.append(
                    "%s has an invalid result document" % row["task_key"]
                )
                continue
            if (
                certificate.get("source") != payload.get("source")
                or certificate.get("library_id")
                != payload.get("library_id")
                or certificate.get("query_fingerprint")
                != payload.get("query_fingerprint")
            ):
                violations.append(
                    "%s certificate identity differs from its task"
                    % row["task_key"]
                )
                continue
            observations = tuple(result.get("observations") or ()) + tuple(
                result.get("quarantined_observations") or ()
            )
            if any(
                not isinstance(observation, Mapping)
                or str(observation.get("visibility")).lower() != "public"
                for observation in observations
            ):
                violations.append(
                    "%s contains non-public discovery evidence"
                    % row["task_key"]
                )
                continue
            partitions = certificate.get("partitions") or ()
            required_complete = (
                certificate.get("complete") is True
                and certificate.get("terminal") is True
                and bool(certificate.get("epoch_completed_at"))
                and not (certificate.get("gaps") or ())
                and all(
                    isinstance(partition, Mapping)
                    and partition.get("complete") is True
                    and not (
                        partition.get("capped") is True
                        and partition.get("subdivided") is not True
                    )
                    for partition in partitions
                )
            )
            if not required_complete:
                violations.append(
                    "%s lacks complete uncapped required-source certification"
                    % row["task_key"]
                )
                continue
            coverage = self.connection.execute(
                """
                SELECT complete, capped
                FROM discovery_coverage
                WHERE run_id=? AND library_id=? AND source=? AND query_fp=?
                """,
                (
                    run_id,
                    payload.get("library_id"),
                    payload.get("source"),
                    payload.get("query_fingerprint"),
                ),
            ).fetchall()
            if not coverage or any(
                item["complete"] != 1 or item["capped"] != 0
                for item in coverage
            ):
                violations.append(
                    "%s lacks current-plan complete coverage rows"
                    % row["task_key"]
                )
        if violations:
            raise RuntimeError(
                "required discovery coverage is not publishable: "
                + "; ".join(violations[:8])
            )

    def discovery_publication_diagnostics(
        self, run_id: str
    ) -> dict[str, Any]:
        """Return required/advisory coverage diagnostics for owner review."""
        if self.connection.execute(
            "SELECT 1 FROM runs WHERE run_id=?", (run_id,)
        ).fetchone() is None:
            raise KeyError(f"unknown run: {run_id}")
        by_source: dict[str, dict[str, int]] = {}
        current_queries = set()
        for row in self.connection.execute(
            """
            SELECT payload_json, result_json FROM tasks
            WHERE run_id=? AND stage='discovery-query'
            """,
            (run_id,),
        ):
            try:
                payload = json.loads(row["payload_json"])
                result = json.loads(row["result_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if result.get("superseded") is True:
                continue
            current_queries.add(
                (
                    payload.get("library_id"),
                    payload.get("source"),
                    payload.get("query_fingerprint"),
                )
            )
        for row in self.connection.execute(
            """
            SELECT library_id, source, query_fp, complete, capped
            FROM discovery_coverage WHERE run_id=?
            """,
            (run_id,),
        ):
            if (
                row["library_id"],
                row["source"],
                row["query_fp"],
            ) not in current_queries:
                continue
            counts = by_source.setdefault(
                str(row["source"]),
                {
                    "rows": 0,
                    "incomplete_rows": 0,
                    "capped_rows": 0,
                },
            )
            counts["rows"] += 1
            counts["incomplete_rows"] += int(row["complete"] != 1)
            counts["capped_rows"] += int(row["capped"] != 0)
        return {"sources": by_source}

    def assert_run_publishable(self, run_id: str) -> None:
        """Apply the run-level release gate without changing run state."""
        with self.transaction():
            self._assert_run_publishable(run_id)

    def finish_run(self, run_id: str, *, status: str) -> None:
        """Finish a run, refusing to call unresolved work complete."""
        if status not in {"complete", "failed", "abandoned"}:
            raise ValueError("terminal run status required")
        with self.transaction(immediate=True):
            if status == "complete":
                self._assert_run_publishable(run_id)
            now = self._now()
            changed = self.connection.execute(
                "UPDATE runs SET status=?, finished_at=?, checkpoint_at=? WHERE run_id=?",
                (status, now, now, run_id),
            ).rowcount
            if changed != 1:
                raise KeyError(f"unknown run: {run_id}")

    def record_discovery_coverage(
        self,
        *,
        run_id: str,
        library_id: str,
        source: str,
        query_fp: str,
        partition_key: str,
        complete: bool,
        result_count: int,
        capped: bool = False,
        lag_seconds: int | None = None,
        gaps: Sequence[Any] = (),
        certificate: Mapping[str, Any] | None = None,
    ) -> None:
        certificate = certificate or {}
        _validate_public_payload(gaps, path="coverage.gaps")
        _validate_public_payload(certificate, path="coverage.certificate")
        certificate_json = _json(certificate)
        with self.transaction(immediate=True):
            # A query retry is a new coverage attempt, not a set of
            # mergeable partition fragments. Remove every row certified by
            # the prior attempt before recording the new document so stale
            # partial work can neither satisfy nor block publication.
            self.connection.execute(
                """
                DELETE FROM discovery_coverage
                WHERE run_id=? AND library_id=? AND source=? AND query_fp=?
                  AND certificate_json != ?
                """,
                (
                    run_id,
                    library_id,
                    source,
                    query_fp,
                    certificate_json,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO discovery_coverage(
                    run_id, library_id, source, query_fp, partition_key,
                    complete, result_count, capped, lag_seconds, gaps_json,
                    certificate_json, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, library_id, source, query_fp, partition_key)
                DO UPDATE SET
                    complete=excluded.complete,
                    result_count=excluded.result_count,
                    capped=excluded.capped,
                    lag_seconds=excluded.lag_seconds,
                    gaps_json=excluded.gaps_json,
                    certificate_json=excluded.certificate_json,
                    observed_at=excluded.observed_at
                """,
                (
                    run_id,
                    library_id,
                    source,
                    query_fp,
                    partition_key,
                    int(complete),
                    int(result_count),
                    int(capped),
                    lag_seconds,
                    _json(list(gaps)),
                    certificate_json,
                    self._now(),
                ),
            )

    def put_citation_cache(
        self,
        *,
        library_id: str,
        query_fp: str,
        work_id: str,
        payload_fp: str,
        payload: Mapping[str, Any] | None,
        sources: Mapping[str, Any] | None,
        status: str,
    ) -> None:
        payload = payload or {}
        sources = sources or {}
        _validate_public_payload(payload, path="citation.payload")
        _validate_public_payload(sources, path="citation.sources")
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                INSERT INTO citation_cache(
                    library_id, query_fp, work_id, payload_fp, payload_json,
                    source_json, status, fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(library_id, query_fp, work_id) DO UPDATE SET
                    payload_fp=excluded.payload_fp,
                    payload_json=excluded.payload_json,
                    source_json=excluded.source_json,
                    status=excluded.status,
                    fetched_at=excluded.fetched_at
                """,
                (
                    library_id,
                    query_fp,
                    work_id,
                    payload_fp,
                    _json(payload),
                    _json(sources),
                    status,
                    self._now(),
                ),
            )

    def record_release(
        self,
        release_id: str,
        *,
        run_id: str | None,
        state_txn: str,
        manifest_path: str | None,
        artifacts: Sequence[Mapping[str, Any]],
        validation: Mapping[str, Any],
        status: str = "staged",
    ) -> None:
        _validate_public_payload(artifacts, path="release.artifacts")
        _validate_public_payload(validation, path="release.validation")
        now = self._now()
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                INSERT INTO releases(
                    release_id, run_id, state_txn, manifest_path,
                    artifacts_json, validation_json, status, created_at,
                    published_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(release_id) DO UPDATE SET
                    run_id=excluded.run_id,
                    state_txn=excluded.state_txn,
                    manifest_path=excluded.manifest_path,
                    artifacts_json=excluded.artifacts_json,
                    validation_json=excluded.validation_json,
                    status=excluded.status,
                    published_at=excluded.published_at
                """,
                (
                    release_id,
                    run_id,
                    state_txn,
                    manifest_path,
                    _json(list(artifacts)),
                    _json(validation),
                    status,
                    now,
                    now if status == "published" else None,
                ),
            )

    def compact_operational_history(
        self,
        *,
        completed_runs: int = 12,
        releases: int = 12,
        citation_versions: int = 2,
        analysis_versions: int = 2,
    ) -> dict[str, int]:
        """Bound append-only operational history without dropping live state."""
        if min(
            completed_runs,
            releases,
            citation_versions,
            analysis_versions,
        ) <= 0:
            raise ValueError("retention counts must be positive")
        deleted: dict[str, int] = {}
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                CREATE TEMP TABLE IF NOT EXISTS retained_runs(
                    run_id TEXT PRIMARY KEY
                ) WITHOUT ROWID
                """
            )
            self.connection.execute("DELETE FROM retained_runs")
            self.connection.execute(
                """
                INSERT OR IGNORE INTO retained_runs
                SELECT run_id FROM runs
                WHERE status IN ('running', 'failed')
                """
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO retained_runs
                SELECT run_id FROM runs
                WHERE status IN ('complete', 'abandoned')
                ORDER BY created_at DESC, run_id DESC
                LIMIT ?
                """,
                (completed_runs,),
            )
            deleted["runs"] = self.connection.execute(
                """
                DELETE FROM runs
                WHERE NOT EXISTS (
                    SELECT 1 FROM retained_runs kept
                    WHERE kept.run_id=runs.run_id
                )
                """
            ).rowcount
            deleted["scan_results"] = self.connection.execute(
                """
                DELETE FROM scan_results
                WHERE NOT EXISTS (
                    SELECT 1 FROM repositories r
                    JOIN libraries l
                      ON l.library_id=scan_results.library_id
                    WHERE r.node_id=scan_results.repository_id
                      AND r.head_sha=scan_results.head_sha
                      AND l.detector_fp=scan_results.detector_fp
                )
                """
            ).rowcount
            deleted["repo_analysis"] = self.connection.execute(
                """
                DELETE FROM repo_analysis
                WHERE analysis_id IN (
                    SELECT analysis_id FROM (
                        SELECT a.analysis_id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY a.repository_id, a.head_sha
                                   ORDER BY a.analyzed_at DESC, a.analysis_id DESC
                               ) AS rank
                        FROM repo_analysis a
                        JOIN repositories r
                          ON r.node_id=a.repository_id
                         AND r.head_sha=a.head_sha
                    ) WHERE rank > ?
                )
                OR NOT EXISTS (
                    SELECT 1 FROM repositories r
                    WHERE r.node_id=repo_analysis.repository_id
                      AND r.head_sha=repo_analysis.head_sha
                )
                """,
                (analysis_versions,),
            ).rowcount
            deleted["citation_cache"] = self.connection.execute(
                """
                DELETE FROM citation_cache
                WHERE query_fp NOT IN (
                    SELECT newer.query_fp
                    FROM citation_cache newer
                    WHERE newer.library_id=citation_cache.library_id
                    GROUP BY newer.query_fp
                    ORDER BY MAX(newer.fetched_at) DESC, newer.query_fp DESC
                    LIMIT ?
                )
                """,
                (citation_versions,),
            ).rowcount
            deleted["releases"] = self.connection.execute(
                """
                DELETE FROM releases
                WHERE status!='staged' AND release_id NOT IN (
                    SELECT release_id FROM releases
                    WHERE status!='staged'
                    ORDER BY created_at DESC, release_id DESC
                    LIMIT ?
                )
                """,
                (releases,),
            ).rowcount
            self.connection.execute("DELETE FROM retained_runs")
        return deleted

    def _scan_attempt_identity(
        self, task: Mapping[str, Any]
    ) -> tuple[str, str] | None:
        """Resolve a public repository and immutable head for a scan lease."""
        if task.get("stage") != "scan":
            return None
        try:
            payload = json.loads(str(task.get("payload_json") or "{}"))
        except (TypeError, ValueError):
            return None
        if not isinstance(payload, Mapping):
            return None

        repository_id = task.get("repository_id")
        payload_repository_ids = tuple(
            value
            for value in (
                payload.get("repository_id"),
                payload.get("repo_node_id"),
                payload.get("node_id"),
            )
            if isinstance(value, str) and value
        )
        if isinstance(repository_id, str) and repository_id:
            if any(
                value != repository_id for value in payload_repository_ids
            ):
                raise RuntimeError(
                    "scan task repository identity changed before lease"
                )
        elif payload_repository_ids:
            if len(set(payload_repository_ids)) != 1:
                raise RuntimeError(
                    "scan task payload has conflicting repository identities"
                )
            repository_id = payload_repository_ids[0]
        else:
            full_name = payload.get("full_name") or payload.get("repo")
            if isinstance(full_name, str) and full_name:
                repository = self.connection.execute(
                    """
                    SELECT node_id FROM repositories
                    WHERE full_name=? COLLATE NOCASE AND visibility='public'
                    """,
                    (full_name,),
                ).fetchone()
                repository_id = (
                    repository["node_id"] if repository is not None else None
                )
        if not isinstance(repository_id, str) or not repository_id:
            # Old or synthetic task rows can remain operable, but their
            # unjournaled usage will fail closed in scan_attempt_usage().
            return None
        repository = self.connection.execute(
            """
            SELECT node_id, head_sha FROM repositories
            WHERE node_id=? AND visibility='public'
            """,
            (repository_id,),
        ).fetchone()
        if repository is None:
            return None
        head_sha = payload.get("head_sha") or repository["head_sha"]
        if not isinstance(head_sha, str) or not head_sha:
            return None
        return str(repository["node_id"]), head_sha

    def _start_scan_attempt(
        self, task: Mapping[str, Any], *, started_at: str
    ) -> bool:
        identity = self._scan_attempt_identity(task)
        if identity is None:
            return False
        repository_id, head_sha = identity
        payload_json = str(task.get("payload_json") or "{}")
        payload_sha256 = hashlib.sha256(
            payload_json.encode("utf-8")
        ).hexdigest()
        self.connection.execute(
            """
            INSERT INTO scan_attempts(
                task_id, attempt, run_id, repository_id, task_key,
                payload_sha256, head_sha, status, retryable,
                usage_complete, started_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', NULL, 0, ?)
            """,
            (
                str(task["task_id"]),
                int(task["attempts"]),
                task["run_id"],
                repository_id,
                task["task_key"],
                payload_sha256,
                head_sha,
                started_at,
            ),
        )
        return True

    def _finish_scan_attempt(
        self,
        task: Mapping[str, Any],
        *,
        status: str,
        retryable: bool,
        error_code: str | None,
        result: Mapping[str, Any] | None,
        finished_at: str,
    ) -> bool:
        if task.get("stage") != "scan":
            return False
        attempt = self.connection.execute(
            """
            SELECT status, retryable, error_code,
                   seconds, current_tree_triage_seconds,
                   history_dating_seconds, analysis_seconds,
                   git_subprocess_count, network_clone_count,
                   network_fetch_count, network_materialized_bytes,
                   usage_complete
            FROM scan_attempts
            WHERE task_id=? AND attempt=?
            """,
            (str(task["task_id"]), int(task["attempts"])),
        ).fetchone()
        if attempt is None:
            # A task leased before v5, or an old synthetic task without an
            # admitted repository/head, has no invented attempt record.
            return False
        usage, usage_complete = _scan_attempt_usage_values(result)
        if attempt["status"] != "running":
            expected = {
                "status": status,
                "retryable": int(bool(retryable)),
                "error_code": error_code,
                **usage,
                "usage_complete": int(usage_complete),
            }
            actual = {
                key: attempt[key]
                for key in expected
            }
            if actual != expected:
                raise RuntimeError(
                    "durable scan attempt result changed before task completion"
                )
            return True
        error_detail = None
        if status == "failed" and isinstance(result, Mapping):
            detail = result.get("error") or result.get("detail")
            if isinstance(detail, str) and detail:
                error_detail = detail[:500]
        changed = self.connection.execute(
            """
            UPDATE scan_attempts SET
                status=?, retryable=?, error_code=?, error_detail=?,
                seconds=?, current_tree_triage_seconds=?,
                history_dating_seconds=?, analysis_seconds=?,
                git_subprocess_count=?, network_clone_count=?,
                network_fetch_count=?, network_materialized_bytes=?,
                usage_complete=?, finished_at=?
            WHERE task_id=? AND attempt=? AND status='running'
            """,
            (
                status,
                int(bool(retryable)),
                error_code,
                error_detail,
                usage["seconds"],
                usage["current_tree_triage_seconds"],
                usage["history_dating_seconds"],
                usage["analysis_seconds"],
                usage["git_subprocess_count"],
                usage["network_clone_count"],
                usage["network_fetch_count"],
                usage["network_materialized_bytes"],
                int(usage_complete),
                finished_at,
                str(task["task_id"]),
                int(task["attempts"]),
            ),
        ).rowcount
        if changed != 1:
            raise RuntimeError("scan attempt changed during completion")
        return True

    def record_scan_attempt_result(
        self,
        task_id: int,
        *,
        worker: str,
        status: str,
        retryable: bool,
        error_code: str | None,
        result: Mapping[str, Any],
        now_epoch: float | None = None,
    ) -> None:
        """Durably charge one finished scan before its verdict transaction.

        The scanner's network and Git usage survives a coordinator crash after
        the worker returns but before scan results and task completion commit.
        A compatible resume may then retry the missing verdict while charging
        the completed attempt exactly once.
        """
        if status not in {"complete", "failed"}:
            raise ValueError("scan attempt status must be complete or failed")
        if status == "complete" and (retryable or error_code is not None):
            raise ValueError(
                "complete scan attempt must be nonretryable without an error"
            )
        if status == "failed" and error_code is None:
            raise ValueError("failed scan attempt requires an error_code")
        if error_code is not None and not re.fullmatch(
            r"[a-z0-9][a-z0-9_.:-]{0,127}", error_code
        ):
            raise ValueError(
                "error_code must be a short machine-readable code"
            )
        _validate_public_payload(result, path="scan_attempt.result")
        _usage, usage_complete = _scan_attempt_usage_values(result)
        if not usage_complete:
            raise ValueError(
                "scan attempt result requires complete non-negative usage"
            )
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        now = self._now()
        with self.transaction(immediate=True):
            task = self.connection.execute(
                """
                SELECT * FROM tasks
                WHERE task_id=? AND stage='scan' AND status='running'
                  AND lease_owner=? AND lease_expires_at > ?
                """,
                (task_id, worker, now_epoch),
            ).fetchone()
            if task is None:
                raise RuntimeError(
                    "scan task lease is absent, expired, or owned by another "
                    "worker"
                )
            task_document = _row_dict(task)
            assert task_document is not None
            if not self._finish_scan_attempt(
                task_document,
                status=status,
                retryable=retryable,
                error_code=error_code,
                result=result,
                finished_at=now,
            ):
                raise RuntimeError("scan attempt has no durable ledger row")

    def enqueue_task(
        self,
        run_id: str,
        stage: str,
        task_key: str,
        *,
        repository_id: str | None = None,
        library_id: str | None = None,
        payload: Mapping[str, Any] | None = None,
        max_attempts: int = 3,
        available_at: float = 0,
    ) -> int:
        payload = payload or {}
        _validate_public_payload(payload, path="task.payload")
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        now = self._now()
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                INSERT INTO tasks(
                    run_id, stage, task_key, repository_id, library_id,
                    payload_json, max_attempts, available_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, stage, task_key) DO NOTHING
                """,
                (
                    run_id,
                    stage,
                    task_key,
                    repository_id,
                    library_id,
                    _json(payload),
                    max_attempts,
                    float(available_at),
                    now,
                    now,
                ),
            )
            row = self.connection.execute(
                "SELECT task_id FROM tasks WHERE run_id=? AND stage=? AND task_key=?",
                (run_id, stage, task_key),
            ).fetchone()
            return int(row["task_id"])

    def supersede_tasks(
        self,
        run_id: str,
        stage: str,
        *,
        keep_task_keys: Sequence[str],
        reason: str,
    ) -> int:
        """Close obsolete immutable work after a compatible run is replanned."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", reason):
            raise ValueError("supersede reason must be machine-readable")
        now = self._now()
        keep = tuple(sorted(set(keep_task_keys)))
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                CREATE TEMP TABLE IF NOT EXISTS selected_task_keys(
                    task_key TEXT PRIMARY KEY
                ) WITHOUT ROWID
                """
            )
            self.connection.execute("DELETE FROM selected_task_keys")
            self.connection.executemany(
                "INSERT INTO selected_task_keys(task_key) VALUES (?)",
                ((key,) for key in keep),
            )
            changed = self.connection.execute(
                """
                UPDATE tasks SET status='complete', lease_owner=NULL,
                    lease_expires_at=NULL, updated_at=?, finished_at=?,
                    result_json=?
                WHERE run_id=? AND stage=? AND status!='complete'
                  AND NOT EXISTS (
                      SELECT 1 FROM selected_task_keys selected
                      WHERE selected.task_key=tasks.task_key
                  )
                """
                ,
                (
                    now,
                    now,
                    _json({"superseded": True, "reason": reason}),
                    run_id,
                    stage,
                ),
            ).rowcount
            self.connection.execute("DELETE FROM selected_task_keys")
            return changed

    def recover_stale_tasks(self, *, now_epoch: float | None = None) -> int:
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        now = self._now()
        with self.transaction(immediate=True):
            self.connection.execute(
                """
                UPDATE scan_attempts SET status='interrupted', retryable=1,
                    error_code='lease_expired', usage_complete=0,
                    finished_at=?
                WHERE status='running' AND EXISTS (
                    SELECT 1 FROM tasks
                    WHERE CAST(tasks.task_id AS TEXT)=scan_attempts.task_id
                      AND tasks.status='running'
                      AND tasks.lease_expires_at <= ?
                )
                """,
                (now, now_epoch),
            )
            stale_tasks = self.connection.execute(
                """
                SELECT * FROM tasks
                WHERE status='running' AND lease_expires_at <= ?
                ORDER BY task_id
                """,
                (now_epoch,),
            ).fetchall()
            for task in stale_tasks:
                if task["stage"] == "scan":
                    status, error_code = (
                        self._scan_task_recovery_disposition(task)
                    )
                else:
                    status = (
                        "failed"
                        if int(task["attempts"]) >= int(task["max_attempts"])
                        else "pending"
                    )
                    error_code = (
                        "lease_expired_max_attempts"
                        if status == "failed"
                        else task["error_code"]
                    )
                self.connection.execute(
                    """
                    UPDATE tasks SET status=?, lease_owner=NULL,
                        lease_expires_at=NULL, error_code=?, updated_at=?,
                        finished_at=?
                    WHERE task_id=?
                    """,
                    (
                        status,
                        error_code,
                        now,
                        now if status == "failed" else None,
                        task["task_id"],
                    ),
                )
            return len(stale_tasks)

    def lease_task(
        self,
        *,
        run_id: str,
        worker: str,
        lease_seconds: float = 600,
        stages: Sequence[str] | None = None,
        now_epoch: float | None = None,
    ) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        with self.transaction(immediate=True):
            self.recover_stale_tasks(now_epoch=now_epoch)
            parameters: list[Any] = [run_id, now_epoch]
            stage_clause = ""
            if stages:
                placeholders = ",".join("?" for _ in stages)
                stage_clause = f" AND stage IN ({placeholders})"
                parameters.extend(stages)
            row = self.connection.execute(
                f"""
                SELECT * FROM tasks
                WHERE run_id=? AND status='pending' AND available_at <= ?
                  AND attempts < max_attempts {stage_clause}
                  AND NOT EXISTS (
                      SELECT 1 FROM scan_attempts
                      WHERE scan_attempts.run_id=tasks.run_id
                        AND scan_attempts.task_id=CAST(tasks.task_id AS TEXT)
                        AND scan_attempts.usage_complete=0
                        AND (
                            scan_attempts.status!='interrupted'
                            OR COALESCE(scan_attempts.retryable, 0)!=1
                        )
                  )
                ORDER BY task_id
                LIMIT 1
                """,
                parameters,
            ).fetchone()
            if row is None:
                return None
            now = self._now()
            updated = self.connection.execute(
                """
                UPDATE tasks SET status='running', attempts=attempts+1,
                    lease_owner=?, lease_expires_at=?, updated_at=?
                WHERE task_id=? AND status='pending'
                """,
                (
                    worker,
                    now_epoch + float(lease_seconds),
                    now,
                    row["task_id"],
                ),
            ).rowcount
            if updated != 1:
                return None
            leased = self.connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (row["task_id"],)
            ).fetchone()
            leased_document = _row_dict(leased)
            assert leased_document is not None
            self._start_scan_attempt(leased_document, started_at=now)
            return leased_document

    def lease_task_by_id(
        self,
        task_id: int,
        *,
        worker: str,
        lease_seconds: float = 600,
        now_epoch: float | None = None,
    ) -> dict[str, Any] | None:
        """Lease one exact task immediately before it is dispatched.

        Large queues are enqueued durably but only worker-slot-sized batches
        become ``running``. This keeps never-started work at zero attempts
        across coordinator or Mac interruptions.
        """
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        with self.transaction(immediate=True):
            self.recover_stale_tasks(now_epoch=now_epoch)
            now = self._now()
            updated = self.connection.execute(
                """
                UPDATE tasks SET status='running', attempts=attempts+1,
                    lease_owner=?, lease_expires_at=?, updated_at=?
                WHERE task_id=? AND status='pending'
                  AND available_at <= ? AND attempts < max_attempts
                  AND NOT EXISTS (
                      SELECT 1 FROM scan_attempts
                      WHERE scan_attempts.run_id=tasks.run_id
                        AND scan_attempts.task_id=CAST(tasks.task_id AS TEXT)
                        AND scan_attempts.usage_complete=0
                        AND (
                            scan_attempts.status!='interrupted'
                            OR COALESCE(scan_attempts.retryable, 0)!=1
                        )
                  )
                """,
                (
                    worker,
                    now_epoch + float(lease_seconds),
                    now,
                    int(task_id),
                    now_epoch,
                ),
            ).rowcount
            if updated != 1:
                return None
            leased = self.connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (int(task_id),)
            ).fetchone()
            leased_document = _row_dict(leased)
            assert leased_document is not None
            self._start_scan_attempt(leased_document, started_at=now)
            return leased_document

    def renew_task(
        self,
        task_id: int,
        *,
        worker: str,
        lease_seconds: float = 600,
        now_epoch: float | None = None,
    ) -> bool:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        with self.transaction(immediate=True):
            changed = self.connection.execute(
                """
                UPDATE tasks SET lease_expires_at=?, updated_at=?
                WHERE task_id=? AND status='running' AND lease_owner=?
                  AND lease_expires_at > ?
                """,
                (
                    now_epoch + lease_seconds,
                    self._now(),
                    task_id,
                    worker,
                    now_epoch,
                ),
            ).rowcount
            return changed == 1

    def complete_task(
        self,
        task_id: int,
        *,
        worker: str,
        result: Mapping[str, Any] | None = None,
        now_epoch: float | None = None,
    ) -> None:
        _validate_public_payload(result or {}, path="task.result")
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        now = self._now()
        with self.transaction(immediate=True):
            task = self.connection.execute(
                """
                SELECT * FROM tasks
                WHERE task_id=? AND status='running' AND lease_owner=?
                  AND lease_expires_at > ?
                """,
                (task_id, worker, now_epoch),
            ).fetchone()
            if task is None:
                raise RuntimeError(
                    "task lease is absent, expired, or owned by another worker"
                )
            task_document = _row_dict(task)
            assert task_document is not None
            self._finish_scan_attempt(
                task_document,
                status="complete",
                retryable=False,
                error_code=None,
                result=result,
                finished_at=now,
            )
            changed = self.connection.execute(
                """
                UPDATE tasks SET status='complete', result_json=?,
                    lease_owner=NULL, lease_expires_at=NULL, error_code=NULL,
                    updated_at=?, finished_at=?
                WHERE task_id=? AND status='running' AND lease_owner=?
                  AND lease_expires_at > ?
                """,
                (_json(result), now, now, task_id, worker, now_epoch),
            ).rowcount
            if changed != 1:
                raise RuntimeError(
                    "task lease is absent, expired, or owned by another worker"
                )

    def fail_task(
        self,
        task_id: int,
        *,
        worker: str,
        error_code: str,
        result: Mapping[str, Any] | None = None,
        retry: bool = True,
        delay_seconds: float = 0,
        now_epoch: float | None = None,
    ) -> str:
        """Fail or requeue a leased task; return its resulting status."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", error_code):
            raise ValueError("error_code must be a short machine-readable code")
        if result is not None:
            _validate_public_payload(result, path="task.failure")
        result_json = None if result is None else _json(result)
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        with self.transaction(immediate=True):
            row = self.connection.execute(
                """
                SELECT * FROM tasks
                WHERE task_id=? AND status='running' AND lease_owner=?
                  AND lease_expires_at > ?
                """,
                (task_id, worker, now_epoch),
            ).fetchone()
            if row is None:
                raise RuntimeError("task lease is absent, expired, or owned by another worker")
            status = (
                "pending"
                if retry and int(row["attempts"]) < int(row["max_attempts"])
                else "failed"
            )
            finished_at = None if status == "pending" else self._now()
            row_document = _row_dict(row)
            assert row_document is not None
            attempt_finished_at = self._now()
            self._finish_scan_attempt(
                row_document,
                status="failed",
                retryable=bool(retry),
                error_code=error_code,
                result=result,
                finished_at=attempt_finished_at,
            )
            self.connection.execute(
                """
                UPDATE tasks SET status=?, lease_owner=NULL, lease_expires_at=NULL,
                    available_at=?, error_code=?, result_json=?,
                    updated_at=?, finished_at=?
                WHERE task_id=?
                """,
                (
                    status,
                    now_epoch + max(0, delay_seconds),
                    error_code,
                    result_json,
                    self._now(),
                    finished_at,
                    task_id,
                ),
            )
            return status

    def record_network_task_usage(
        self,
        *,
        run_id: str,
        task_id: int,
        attempt: int,
        source: str,
        result_status: str,
        operation_count: int,
        request_attempt_count: int,
        retry_count: int,
        rate_limited_attempts: int,
        server_error_attempts: int,
        network_error_attempts: int,
        budget_rejections: int,
    ) -> bool:
        """Journal one discovery attempt's aggregate, secret-free HTTP use.

        The task result and coverage certificate describe logical discovery
        work. This row separately preserves actual HTTP attempts—including
        retries and failed task attempts—so a process restart or audited
        successor cannot silently reset the run's request budget.
        """
        if source not in {"github-code-search", "sourcegraph"}:
            raise ValueError("invalid network-task usage source")
        if result_status not in {"complete", "failed"}:
            raise ValueError("invalid network-task usage status")
        values = {
            "operation_count": operation_count,
            "request_attempt_count": request_attempt_count,
            "retry_count": retry_count,
            "rate_limited_attempts": rate_limited_attempts,
            "server_error_attempts": server_error_attempts,
            "network_error_attempts": network_error_attempts,
            "budget_rejections": budget_rejections,
        }
        if attempt <= 0 or any(
            not isinstance(value, int) or value < 0
            for value in values.values()
        ):
            raise ValueError("network-task usage counts must be non-negative")
        now = self._now()
        with self.transaction(immediate=True):
            task = self.connection.execute(
                """
                SELECT run_id, stage, attempts FROM tasks
                WHERE task_id=?
                """,
                (int(task_id),),
            ).fetchone()
            if task is None:
                raise KeyError("network-task usage task is unknown")
            if (
                task["run_id"] != run_id
                or task["stage"] != "discovery-query"
                or int(task["attempts"]) != int(attempt)
            ):
                raise RuntimeError(
                    "network-task usage does not match the journaled attempt"
                )
            existing = self.connection.execute(
                """
                SELECT * FROM network_task_usage
                WHERE task_id=? AND attempt=?
                """,
                (int(task_id), int(attempt)),
            ).fetchone()
            expected = {
                "run_id": run_id,
                "task_id": int(task_id),
                "attempt": int(attempt),
                "source": source,
                "result_status": result_status,
                **values,
            }
            if existing is not None:
                if any(existing[key] != value for key, value in expected.items()):
                    raise RuntimeError(
                        "network-task usage differs from its recorded attempt"
                    )
                return False
            self.connection.execute(
                """
                INSERT INTO network_task_usage(
                    run_id, task_id, attempt, source, result_status,
                    operation_count, request_attempt_count, retry_count,
                    rate_limited_attempts, server_error_attempts,
                    network_error_attempts, budget_rejections, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    int(task_id),
                    int(attempt),
                    source,
                    result_status,
                    values["operation_count"],
                    values["request_attempt_count"],
                    values["retry_count"],
                    values["rate_limited_attempts"],
                    values["server_error_attempts"],
                    values["network_error_attempts"],
                    values["budget_rejections"],
                    now,
                ),
            )
        return True

    def scan_attempt_usage(self, run_id: str) -> dict[str, int | float | bool]:
        """Return complete durable scan usage or refuse an unknown total.

        Missing v5 rows and interrupted/partial attempt metrics are never
        interpreted as zero. Callers can therefore use this aggregate as a
        hard budget input without silently losing work across a restart.
        """
        run = self.connection.execute(
            "SELECT 1 FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        if run is None:
            raise KeyError(f"unknown run: {run_id}")
        expected_attempts = int(
            self.connection.execute(
                """
                SELECT COALESCE(SUM(attempts), 0) FROM tasks
                WHERE run_id=? AND stage='scan'
                """,
                (run_id,),
            ).fetchone()[0]
        )
        rows = self.connection.execute(
            """
            SELECT status, usage_complete, seconds,
                   current_tree_triage_seconds, history_dating_seconds,
                   analysis_seconds, git_subprocess_count,
                   network_clone_count, network_fetch_count,
                   network_materialized_bytes
            FROM scan_attempts
            WHERE run_id=?
            ORDER BY task_id, attempt
            """,
            (run_id,),
        ).fetchall()
        if len(rows) != expected_attempts:
            raise RuntimeError(
                "scan attempt usage is incomplete or unknown"
            )
        unknown_rows = [
            row for row in rows if row["usage_complete"] != 1
        ]
        if any(row["status"] != "interrupted" for row in unknown_rows):
            # A live attempt or a malformed completed receipt is not a
            # durable unknown.  Only a coordinator/lease interruption has a
            # closed status that can be charged explicitly and retried.
            raise RuntimeError(
                "scan attempt usage is incomplete or unknown"
            )
        status_counts = {
            "complete_attempts": 0,
            "failed_attempts": 0,
            "interrupted_attempts": 0,
        }
        totals: dict[str, int | float | bool] = {
            "usage_complete": True,
            "attempt_count": len(rows),
            "exact_attempt_count": len(rows) - len(unknown_rows),
            "irreconstructible_attempt_count": len(unknown_rows),
            "timing_known_attempt_count": len(rows) - len(unknown_rows),
            "timing_unknown_attempt_count": len(unknown_rows),
            **status_counts,
            **{field: 0.0 for field in _SCAN_ATTEMPT_FLOAT_FIELDS},
            **{field: 0 for field in _SCAN_ATTEMPT_COUNT_FIELDS},
            "git_subprocess_unknown_attempt_count": len(unknown_rows),
            "network_clone_unknown_attempt_count": len(unknown_rows),
            "network_fetch_unknown_attempt_count": len(unknown_rows),
            "network_materialized_bytes_unknown_attempt_count": len(
                unknown_rows
            ),
        }
        for row in rows:
            status_key = row["status"] + "_attempts"
            if status_key in status_counts:
                totals[status_key] = int(totals[status_key]) + 1
            if row["usage_complete"] != 1:
                continue
            for field in _SCAN_ATTEMPT_FLOAT_FIELDS:
                totals[field] = float(totals[field]) + float(row[field])
            for field in _SCAN_ATTEMPT_COUNT_FIELDS:
                totals[field] = int(totals[field]) + int(row[field])
        return totals

    def acquire_lock(
        self,
        name: str,
        *,
        owner: str,
        lease_seconds: float = 600,
        now_epoch: float | None = None,
    ) -> bool:
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        with self.transaction(immediate=True):
            row = self.connection.execute(
                "SELECT owner, lease_expires_at FROM runtime_locks WHERE lock_name=?",
                (name,),
            ).fetchone()
            if row is not None and row["owner"] != owner and row["lease_expires_at"] > now_epoch:
                return False
            self.connection.execute(
                """
                INSERT INTO runtime_locks(lock_name, owner, lease_expires_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(lock_name) DO UPDATE SET
                    owner=excluded.owner,
                    lease_expires_at=excluded.lease_expires_at,
                    updated_at=excluded.updated_at
                """,
                (name, owner, now_epoch + lease_seconds, self._now()),
            )
            return True

    def release_lock(self, name: str, *, owner: str) -> bool:
        with self.transaction(immediate=True):
            return (
                self.connection.execute(
                    "DELETE FROM runtime_locks WHERE lock_name=? AND owner=?",
                    (name, owner),
                ).rowcount
                == 1
            )

    def renew_lock(
        self,
        name: str,
        *,
        owner: str,
        lease_seconds: float = 600,
        now_epoch: float | None = None,
    ) -> bool:
        """Extend a live lease without ever resurrecting an expired owner."""
        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        with self.transaction(immediate=True):
            return (
                self.connection.execute(
                    """
                    UPDATE runtime_locks
                    SET lease_expires_at=?, updated_at=?
                    WHERE lock_name=? AND owner=? AND lease_expires_at>?
                    """,
                    (
                        now_epoch + max(0.0, float(lease_seconds)),
                        self._now(),
                        name,
                        owner,
                        now_epoch,
                    ),
                ).rowcount
                == 1
            )

    _CHECKPOINT_TABLES: tuple[tuple[str, tuple[str, ...], str], ...] = (
        (
            "repositories",
            (
                "node_id",
                "full_name",
                "visibility",
                "is_fork",
                "is_archived",
                "default_branch",
                "head_sha",
                "metadata_json",
                "etag",
                "first_seen_at",
                "last_seen_at",
                "metadata_checked_at",
            ),
            "node_id",
        ),
        (
            "libraries",
            (
                "library_id",
                "catalog_json",
                "discovery_fp",
                "detector_fp",
                "citation_fp",
                "dating_fp",
                "aggregation_fp",
                "presentation_fp",
                "release_fp",
                "active",
                "updated_at",
            ),
            "library_id",
        ),
        (
            "catalog_events",
            (
                "library_id",
                "catalog_version",
                "observed_on",
                "event",
                "name",
                "catalog_status",
                "source",
                "provenance",
                "effective_on",
                "note",
                "recorded_at",
            ),
            "library_id, observed_on, catalog_version, event",
        ),
        (
            "runs",
            (
                "run_id",
                "mode",
                "plan_json",
                "budgets_json",
                "fingerprints_json",
                "base_release_id",
                "status",
                "started_at",
                "finished_at",
                "checkpoint_at",
                "created_at",
            ),
            "run_id",
        ),
        (
            "run_lineage",
            (
                "successor_run_id",
                "predecessor_run_id",
                "reason",
                "compatibility_sha256",
                "compatibility_json",
                "created_at",
            ),
            "successor_run_id",
        ),
        (
            "stages",
            (
                "run_id",
                "stage",
                "status",
                "counters_json",
                "metrics_json",
                "checkpoint_json",
                "started_at",
                "finished_at",
                "updated_at",
            ),
            "run_id, stage",
        ),
        (
            "candidates",
            (
                "candidate_id",
                "repository_id",
                "library_id",
                "source",
                "query_fp",
                "signal",
                "path",
                "ref",
                "first_seen_at",
                "last_seen_at",
                "coverage_epoch",
                "state",
            ),
            "candidate_id",
        ),
        (
            "scan_results",
            (
                "scan_result_id",
                "repository_id",
                "library_id",
                "head_sha",
                "detector_fp",
                "classification",
                "status",
                "evidence_json",
                "raw_first_commit",
                "raw_first_date",
                "derived_first_date",
                "scanned_at",
            ),
            "scan_result_id",
        ),
        (
            "repo_analysis",
            (
                "analysis_id",
                "repository_id",
                "head_sha",
                "ai_fp",
                "cff_fp",
                "analysis_json",
                "status",
                "analyzed_at",
            ),
            "analysis_id",
        ),
        (
            "tasks",
            (
                "task_id",
                "run_id",
                "stage",
                "task_key",
                "repository_id",
                "library_id",
                "payload_json",
                "result_json",
                "status",
                "attempts",
                "max_attempts",
                "lease_owner",
                "lease_expires_at",
                "available_at",
                "error_code",
                "created_at",
                "updated_at",
                "finished_at",
            ),
            "task_id",
        ),
        (
            "scan_attempts",
            (
                "task_id",
                "attempt",
                "run_id",
                "repository_id",
                "task_key",
                "payload_sha256",
                "head_sha",
                "status",
                "retryable",
                "error_code",
                "error_detail",
                "seconds",
                "current_tree_triage_seconds",
                "history_dating_seconds",
                "analysis_seconds",
                "git_subprocess_count",
                "network_clone_count",
                "network_fetch_count",
                "network_materialized_bytes",
                "usage_complete",
                "started_at",
                "finished_at",
            ),
            "task_id, attempt",
        ),
        (
            "task_inheritance",
            (
                "successor_task_id",
                "successor_run_id",
                "predecessor_run_id",
                "predecessor_task_id",
                "stage",
                "task_key",
                "payload_sha256",
                "result_sha256",
                "network_task_source_sha256",
                "source_policy",
                "inherited_request_count",
                "created_at",
            ),
            "successor_task_id",
        ),
        (
            "network_task_usage",
            (
                "run_id",
                "task_id",
                "attempt",
                "source",
                "result_status",
                "operation_count",
                "request_attempt_count",
                "retry_count",
                "rate_limited_attempts",
                "server_error_attempts",
                "network_error_attempts",
                "budget_rejections",
                "recorded_at",
            ),
            "run_id, task_id, attempt",
        ),
        (
            "discovery_coverage",
            (
                "run_id",
                "library_id",
                "source",
                "query_fp",
                "partition_key",
                "complete",
                "result_count",
                "capped",
                "lag_seconds",
                "gaps_json",
                "certificate_json",
                "observed_at",
            ),
            "run_id, library_id, source, query_fp, partition_key",
        ),
        (
            "citation_cache",
            (
                "library_id",
                "query_fp",
                "work_id",
                "payload_fp",
                "payload_json",
                "source_json",
                "status",
                "fetched_at",
            ),
            "library_id, query_fp, work_id",
        ),
        (
            "releases",
            (
                "release_id",
                "run_id",
                "state_txn",
                "manifest_path",
                "artifacts_json",
                "validation_json",
                "status",
                "created_at",
                "published_at",
            ),
            "release_id",
        ),
    )

    def checkpoint_document(self) -> dict[str, Any]:
        """Return deterministic durable state, excluding ephemeral run locks."""
        tables: dict[str, Any] = {}
        with self.transaction():
            repository_rows = [
                dict(row)
                for row in self.connection.execute(
                    """
                    SELECT node_id, full_name, visibility, is_fork, is_archived,
                           default_branch, head_sha, metadata_json, etag,
                           first_seen_at, last_seen_at, metadata_checked_at
                    FROM repositories
                    WHERE visibility='public'
                    ORDER BY node_id
                    """
                )
            ]
            public_node_ids, public_names = (
                _checkpoint_public_identities(repository_rows)
            )
            for table, columns, order_by in self._CHECKPOINT_TABLES:
                quoted_columns = ", ".join(columns)
                rows = [
                    dict(row)
                    for row in self.connection.execute(
                        f"SELECT {quoted_columns} FROM {table} ORDER BY {order_by}"
                    )
                ]
                # Defense in depth if an old/malformed DB bypassed schema admission.
                if table == "repositories":
                    rows = [row for row in rows if row["visibility"] == "public"]
                elif table in {
                    "runs", "stages", "tasks", "scan_attempts"
                }:
                    rows = [
                        sanitized
                        for row in rows
                        if (
                            sanitized := _sanitize_checkpoint_operational_row(
                                table,
                                row,
                                public_node_ids=public_node_ids,
                                public_names=public_names,
                            )
                        )
                        is not None
                    ]
                tables[table] = {"columns": list(columns), "rows": rows}
        return {
            "format": CHECKPOINT_FORMAT_VERSION,
            "schema_version": self.schema_version,
            "tables": tables,
        }

    def checkpoint_bytes(self) -> bytes:
        return (canonical_json(self.checkpoint_document()) + "\n").encode("utf-8")

    def export_checkpoint(self, destination: str | os.PathLike[str]) -> Path:
        """Atomically export one deterministic, public-only JSON checkpoint."""
        target = Path(destination).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.tmp-{os.getpid()}")
        with open(tmp, "wb") as stream:
            stream.write(self.checkpoint_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, target)
        return target

    def export_checkpoint_shards(
        self,
        destination: str | os.PathLike[str],
        *,
        rows_per_shard: int = 1000,
        target_bytes: int = CHECKPOINT_TARGET_BYTES,
    ) -> Path:
        """Stream deterministic bounded shards and publish ``manifest.json`` last."""
        if rows_per_shard <= 0:
            raise ValueError("rows_per_shard must be positive")
        if not (0 < target_bytes < 4_000_000):
            raise ValueError("checkpoint shard target must be <4,000,000 bytes")
        target = Path(destination).expanduser().resolve()
        target.mkdir(parents=True, exist_ok=True)
        manifest: dict[str, Any] = {
            "format": CHECKPOINT_FORMAT_VERSION,
            "schema_version": self.schema_version,
            "shards": [],
        }
        expected_files: set[str] = {"manifest.json"}

        def emit(table, columns, index, chunk):
            payload = (
                canonical_json(
                    {"table": table, "columns": list(columns), "rows": chunk}
                )
                + "\n"
            ).encode("utf-8")
            if len(payload) > target_bytes:
                raise ValueError(
                    f"checkpoint row/shard exceeds {target_bytes} bytes: {table}"
                )
            digest = hashlib.sha256(payload).hexdigest()
            name = f"{table}-{index:05d}-{digest[:16]}.json"
            shard_path = target / name
            tmp = target / f".{name}.tmp-{os.getpid()}"
            with open(tmp, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, shard_path)
            expected_files.add(name)
            manifest["shards"].append(
                {
                    "bytes": len(payload),
                    "file": name,
                    "ordinal": index,
                    "rows": len(chunk),
                    "sha256": digest,
                    "table": table,
                }
            )

        with self.transaction():
            repository_rows = [
                dict(row)
                for row in self.connection.execute(
                    """
                    SELECT node_id, full_name, visibility, is_fork, is_archived,
                           default_branch, head_sha, metadata_json, etag,
                           first_seen_at, last_seen_at, metadata_checked_at
                    FROM repositories
                    WHERE visibility='public'
                    ORDER BY node_id
                    """
                )
            ]
            public_node_ids, public_names = (
                _checkpoint_public_identities(repository_rows)
            )
            for table, columns, order_by in sorted(
                self._CHECKPOINT_TABLES, key=lambda item: item[0]
            ):
                sentinel = "__REQ14_CHECKPOINT_ROWS__"
                framed = canonical_json(
                    {
                        "table": table,
                        "columns": list(columns),
                        "rows": sentinel,
                    }
                ).encode("utf-8")
                marker = json.dumps(sentinel).encode("ascii")
                if framed.count(marker) != 1:
                    raise RuntimeError("checkpoint shard framing failed")
                prefix, suffix = framed.split(marker)
                prefix += b"["
                suffix = b"]" + suffix + b"\n"
                fixed_bytes = len(prefix) + len(suffix)
                quoted_columns = ", ".join(columns)
                where = (
                    " WHERE visibility='public'"
                    if table == "repositories"
                    else ""
                )
                cursor = self.connection.execute(
                    f"SELECT {quoted_columns} FROM {table}{where} "
                    f"ORDER BY {order_by}"
                )
                ordinal = 0
                chunk: list[dict[str, Any]] = []
                chunk_bytes = fixed_bytes
                for raw_row in cursor:
                    row = dict(raw_row)
                    if table in {
                        "runs", "stages", "tasks", "scan_attempts"
                    }:
                        row = _sanitize_checkpoint_operational_row(
                            table,
                            row,
                            public_node_ids=public_node_ids,
                            public_names=public_names,
                        )
                        if row is None:
                            continue
                    encoded_row = canonical_json(row).encode("utf-8")
                    single_bytes = fixed_bytes + len(encoded_row)
                    if single_bytes > target_bytes:
                        raise ValueError(
                            "checkpoint row exceeds artifact limit: "
                            f"{table}"
                        )
                    added_bytes = len(encoded_row) + (1 if chunk else 0)
                    if chunk and (
                        len(chunk) >= rows_per_shard
                        or chunk_bytes + added_bytes > target_bytes
                    ):
                        emit(table, columns, ordinal, chunk)
                        ordinal += 1
                        chunk = [row]
                        chunk_bytes = single_bytes
                    else:
                        chunk.append(row)
                        chunk_bytes += added_bytes
                if chunk or ordinal == 0:
                    emit(table, columns, ordinal, chunk)
        manifest_payload = (canonical_json(manifest) + "\n").encode("utf-8")
        if len(manifest_payload) > CHECKPOINT_HARD_BYTES:
            raise ValueError("checkpoint manifest exceeds 5 MiB")
        manifest_tmp = target / f".manifest.json.tmp-{os.getpid()}"
        with open(manifest_tmp, "wb") as stream:
            stream.write(manifest_payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(manifest_tmp, target / "manifest.json")
        # The new manifest is durable, so superseded content-addressed shards
        # can now be removed without creating a torn checkpoint.
        for existing in target.glob("*.json"):
            if existing.name not in expected_files:
                existing.unlink()
        return target

    def import_checkpoint(
        self,
        source: str | os.PathLike[str],
        *,
        replace: bool = False,
    ) -> None:
        """Import a trusted checkpoint after schema and public-only validation."""
        path = Path(source).expanduser().resolve()
        if path.is_dir():
            document = self._read_sharded_checkpoint(path)
        else:
            with open(path, "rb") as stream:
                document = json.load(stream)
        self._validate_checkpoint(document)
        table_order = [table for table, _, _ in self._CHECKPOINT_TABLES]
        with self.transaction(immediate=True):
            if replace:
                for table in reversed(table_order):
                    self.connection.execute(f"DELETE FROM {table}")
                self.connection.execute("DELETE FROM runtime_locks")
            else:
                populated = [
                    table
                    for table in table_order
                    if self.connection.execute(
                        f"SELECT 1 FROM {table} LIMIT 1"
                    ).fetchone()
                    is not None
                ]
                if populated:
                    raise RuntimeError(
                        "checkpoint import target is not empty; pass replace=True"
                    )
            for table in table_order:
                table_data = document["tables"].get(table)
                if not table_data:
                    continue
                columns = table_data["columns"]
                expected = next(
                    cols for name, cols, _ in self._CHECKPOINT_TABLES if name == table
                )
                if tuple(columns) != expected:
                    raise ValueError(f"checkpoint columns differ for {table}")
                placeholders = ",".join("?" for _ in columns)
                column_sql = ",".join(columns)
                for row in table_data["rows"]:
                    self.connection.execute(
                        f"INSERT INTO {table}({column_sql}) VALUES ({placeholders})",
                        tuple(row[column] for column in columns),
                    )

    def _read_sharded_checkpoint(self, path: Path) -> dict[str, Any]:
        manifest_payload = (path / "manifest.json").read_bytes()
        if len(manifest_payload) > CHECKPOINT_HARD_BYTES:
            raise ValueError("checkpoint manifest exceeds 5 MiB")
        manifest = json.loads(manifest_payload)
        if set(manifest) != {"format", "schema_version", "shards"}:
            raise ValueError("checkpoint manifest shape is invalid")
        if not isinstance(manifest["shards"], list):
            raise ValueError("checkpoint shard list is invalid")
        tables: dict[str, dict[str, Any]] = {}
        seen_files: set[str] = set()
        seen_ordinals: dict[str, set[int]] = {}
        expected_files = {"manifest.json"}
        for shard in manifest["shards"]:
            if not isinstance(shard, Mapping) or set(shard) != {
                "bytes", "file", "ordinal", "rows", "sha256", "table"
            }:
                raise ValueError("checkpoint shard descriptor is invalid")
            shard_name = shard["file"]
            if Path(shard_name).name != shard_name:
                raise ValueError("checkpoint shard path must be a plain filename")
            if shard_name in seen_files:
                raise ValueError("checkpoint shard file is duplicated")
            seen_files.add(shard_name)
            expected_files.add(shard_name)
            table = shard["table"]
            ordinal = shard["ordinal"]
            if not isinstance(table, str) or not isinstance(ordinal, int):
                raise ValueError("checkpoint shard identity is invalid")
            ordinals = seen_ordinals.setdefault(table, set())
            if ordinal in ordinals:
                raise ValueError("checkpoint shard ordinal is duplicated")
            ordinals.add(ordinal)
            payload = (path / shard_name).read_bytes()
            if len(payload) != shard["bytes"]:
                raise ValueError(f"checkpoint shard byte count mismatch: {shard_name}")
            if len(payload) > CHECKPOINT_TARGET_BYTES:
                raise ValueError(f"checkpoint shard exceeds artifact limit: {shard_name}")
            if hashlib.sha256(payload).hexdigest() != shard["sha256"]:
                raise ValueError(f"checkpoint shard hash mismatch: {shard_name}")
            content = json.loads(payload)
            if not isinstance(content, Mapping) or set(content) != {
                "columns", "rows", "table"
            }:
                raise ValueError(f"checkpoint shard shape is invalid: {shard_name}")
            if content["table"] != shard["table"]:
                raise ValueError(f"checkpoint shard table mismatch: {shard_name}")
            if len(content.get("rows", [])) != shard["rows"]:
                raise ValueError(f"checkpoint shard row count mismatch: {shard_name}")
            aggregate = tables.setdefault(
                content["table"], {"columns": content["columns"], "rows": []}
            )
            if aggregate["columns"] != content["columns"]:
                raise ValueError("checkpoint shard columns disagree")
            aggregate["rows"].extend(content["rows"])
        allowed = {table for table, _, _ in self._CHECKPOINT_TABLES}
        if set(tables) != allowed:
            raise ValueError("checkpoint does not contain every required table")
        for table, ordinals in seen_ordinals.items():
            if ordinals != set(range(len(ordinals))):
                raise ValueError(
                    f"checkpoint shard ordinals are not contiguous: {table}"
                )
        actual_files = {
            item.name for item in path.iterdir()
            if item.is_file() and item.suffix == ".json"
        }
        if actual_files != expected_files:
            raise ValueError("checkpoint directory closure is invalid")
        return {
            "format": manifest.get("format"),
            "schema_version": manifest.get("schema_version"),
            "tables": tables,
        }

    def _validate_checkpoint(self, document: Mapping[str, Any]) -> None:
        if document.get("format") != CHECKPOINT_FORMAT_VERSION:
            raise ValueError("unsupported checkpoint format")
        if document.get("schema_version") != self.schema_version:
            raise ValueError("checkpoint schema differs from database")
        tables = document.get("tables")
        if not isinstance(tables, Mapping):
            raise ValueError("checkpoint tables missing")
        allowed = {table for table, _, _ in self._CHECKPOINT_TABLES}
        if set(tables) != allowed:
            raise ValueError(
                "checkpoint must contain exactly the public durable tables"
            )
        json_columns = {
            "metadata_json",
            "catalog_json",
            "plan_json",
            "budgets_json",
            "fingerprints_json",
            "counters_json",
            "metrics_json",
            "checkpoint_json",
            "payload_json",
            "result_json",
            "evidence_json",
            "analysis_json",
            "gaps_json",
            "certificate_json",
            "source_json",
            "artifacts_json",
            "validation_json",
        }
        expected_by_table = {
            table: columns
            for table, columns, _order_by in self._CHECKPOINT_TABLES
        }
        repository_table = tables.get("repositories")
        repository_rows = (
            repository_table.get("rows")
            if isinstance(repository_table, Mapping)
            else ()
        )
        if not isinstance(repository_rows, list):
            raise ValueError("checkpoint repository rows are malformed")
        public_node_ids, public_names = _checkpoint_public_identities(
            [
                row
                for row in repository_rows
                if isinstance(row, Mapping)
            ]
        )
        for table, table_data in tables.items():
            if not isinstance(table_data, Mapping):
                raise ValueError(f"checkpoint table is malformed: {table}")
            columns = table_data.get("columns")
            rows = table_data.get("rows")
            if tuple(columns or ()) != expected_by_table[table]:
                raise ValueError(f"checkpoint columns differ for {table}")
            if not isinstance(rows, list):
                raise ValueError(f"checkpoint rows are malformed: {table}")
            for index, row in enumerate(rows):
                if not isinstance(row, Mapping) or set(row) != set(columns):
                    raise ValueError(f"checkpoint row is malformed: {table}")
                if table == "repositories" and row.get("visibility") != "public":
                    raise ValueError("checkpoint contains a non-public repository")
                if table in {
                    "runs", "stages", "tasks", "scan_attempts"
                }:
                    sanitized = _sanitize_checkpoint_operational_row(
                        table,
                        row,
                        public_node_ids=public_node_ids,
                        public_names=public_names,
                    )
                    if sanitized is None or sanitized != dict(row):
                        raise ValueError(
                            "checkpoint contains an unadmitted task identity"
                        )
                _validate_public_payload(
                    row, path=f"checkpoint.{table}[{index}]"
                )
                for column in json_columns.intersection(columns):
                    raw = row.get(column)
                    if raw is None and column == "result_json":
                        continue
                    if not isinstance(raw, str):
                        raise ValueError(
                            f"checkpoint JSON column is malformed: {table}.{column}"
                        )
                    try:
                        payload = json.loads(raw)
                    except (TypeError, ValueError) as exc:
                        raise ValueError(
                            f"checkpoint JSON column is invalid: {table}.{column}"
                        ) from exc
                    _validate_public_payload(
                        payload,
                        path=f"checkpoint.{table}[{index}].{column}",
                    )


def open_state(path: str | os.PathLike[str]) -> StateDB:
    return StateDB(path)
