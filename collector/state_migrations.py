"""Versioned SQLite schema migrations for the REQ-14 operational state.

The migration runner deliberately contains no collector policy.  It accepts an
already-open connection, runs each pending migration in one transaction, and
records the version only after all statements succeed.  Statements in a
migration must therefore be safe to execute after a process crash.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable


SCHEMA_VERSION = 5


MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS repositories (
            node_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL UNIQUE,
            visibility TEXT NOT NULL CHECK (visibility = 'public'),
            is_fork INTEGER NOT NULL DEFAULT 0 CHECK (is_fork IN (0, 1)),
            is_archived INTEGER NOT NULL DEFAULT 0 CHECK (is_archived IN (0, 1)),
            default_branch TEXT,
            head_sha TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            etag TEXT,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            metadata_checked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS libraries (
            library_id TEXT PRIMARY KEY,
            catalog_json TEXT NOT NULL DEFAULT '{}',
            discovery_fp TEXT NOT NULL,
            detector_fp TEXT NOT NULL,
            citation_fp TEXT NOT NULL,
            dating_fp TEXT NOT NULL,
            aggregation_fp TEXT NOT NULL,
            presentation_fp TEXT NOT NULL,
            release_fp TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS candidates (
            candidate_id INTEGER PRIMARY KEY,
            repository_id TEXT NOT NULL REFERENCES repositories(node_id) ON DELETE CASCADE,
            library_id TEXT NOT NULL REFERENCES libraries(library_id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            query_fp TEXT NOT NULL,
            signal TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '',
            ref TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            coverage_epoch TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'active'
                CHECK (state IN ('active', 'stale', 'rejected')),
            UNIQUE (repository_id, library_id, source, query_fp, signal, path, ref)
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            scan_result_id INTEGER PRIMARY KEY,
            repository_id TEXT NOT NULL REFERENCES repositories(node_id) ON DELETE CASCADE,
            library_id TEXT NOT NULL REFERENCES libraries(library_id) ON DELETE CASCADE,
            head_sha TEXT NOT NULL,
            detector_fp TEXT NOT NULL,
            classification TEXT NOT NULL
                CHECK (classification IN
                    ('confirmed', 'bundled', 'targeted', 'rejected', 'transitive')),
            status TEXT NOT NULL
                CHECK (status IN ('clean', 'error', 'gone', 'quarantined')),
            evidence_json TEXT NOT NULL DEFAULT '{}',
            raw_first_commit TEXT,
            raw_first_date TEXT,
            derived_first_date TEXT,
            scanned_at TEXT NOT NULL,
            UNIQUE (repository_id, library_id, head_sha, detector_fp)
        );

        CREATE TABLE IF NOT EXISTS repo_analysis (
            analysis_id INTEGER PRIMARY KEY,
            repository_id TEXT NOT NULL REFERENCES repositories(node_id) ON DELETE CASCADE,
            head_sha TEXT NOT NULL,
            ai_fp TEXT NOT NULL,
            cff_fp TEXT NOT NULL,
            analysis_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL CHECK (status IN ('clean', 'error')),
            analyzed_at TEXT NOT NULL,
            UNIQUE (repository_id, head_sha, ai_fp, cff_fp)
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            mode TEXT NOT NULL,
            plan_json TEXT NOT NULL DEFAULT '{}',
            budgets_json TEXT NOT NULL DEFAULT '{}',
            fingerprints_json TEXT NOT NULL DEFAULT '{}',
            base_release_id TEXT,
            status TEXT NOT NULL
                CHECK (status IN ('planned', 'running', 'failed', 'complete', 'abandoned')),
            started_at TEXT,
            finished_at TEXT,
            checkpoint_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stages (
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            stage TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK (status IN ('pending', 'running', 'failed', 'complete')),
            counters_json TEXT NOT NULL DEFAULT '{}',
            metrics_json TEXT NOT NULL DEFAULT '{}',
            checkpoint_json TEXT NOT NULL DEFAULT '{}',
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (run_id, stage)
        );

        CREATE TABLE IF NOT EXISTS tasks (
            task_id INTEGER PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            stage TEXT NOT NULL,
            task_key TEXT NOT NULL,
            repository_id TEXT REFERENCES repositories(node_id) ON DELETE CASCADE,
            library_id TEXT REFERENCES libraries(library_id) ON DELETE CASCADE,
            payload_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'complete', 'failed')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
            lease_owner TEXT,
            lease_expires_at REAL,
            available_at REAL NOT NULL DEFAULT 0,
            error_code TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            finished_at TEXT,
            UNIQUE (run_id, stage, task_key)
        );

        CREATE TABLE IF NOT EXISTS discovery_coverage (
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            library_id TEXT NOT NULL REFERENCES libraries(library_id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            query_fp TEXT NOT NULL,
            partition_key TEXT NOT NULL,
            complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
            result_count INTEGER NOT NULL DEFAULT 0 CHECK (result_count >= 0),
            capped INTEGER NOT NULL DEFAULT 0 CHECK (capped IN (0, 1)),
            lag_seconds INTEGER,
            gaps_json TEXT NOT NULL DEFAULT '[]',
            certificate_json TEXT NOT NULL DEFAULT '{}',
            observed_at TEXT NOT NULL,
            PRIMARY KEY (run_id, library_id, source, query_fp, partition_key)
        );

        CREATE TABLE IF NOT EXISTS citation_cache (
            library_id TEXT NOT NULL REFERENCES libraries(library_id) ON DELETE CASCADE,
            query_fp TEXT NOT NULL,
            work_id TEXT NOT NULL,
            payload_fp TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            source_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL CHECK (status IN ('fresh', 'stale', 'error')),
            fetched_at TEXT NOT NULL,
            PRIMARY KEY (library_id, query_fp, work_id)
        );

        CREATE TABLE IF NOT EXISTS releases (
            release_id TEXT PRIMARY KEY,
            run_id TEXT REFERENCES runs(run_id) ON DELETE SET NULL,
            state_txn TEXT NOT NULL,
            manifest_path TEXT,
            artifacts_json TEXT NOT NULL DEFAULT '[]',
            validation_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL
                CHECK (status IN ('staged', 'validated', 'published', 'rejected')),
            created_at TEXT NOT NULL,
            published_at TEXT
        );

        CREATE TABLE IF NOT EXISTS runtime_locks (
            lock_name TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            lease_expires_at REAL NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS candidates_library_state
            ON candidates(library_id, state);
        CREATE INDEX IF NOT EXISTS candidates_repository
            ON candidates(repository_id);
        CREATE INDEX IF NOT EXISTS scan_results_reusable
            ON scan_results(repository_id, head_sha, library_id, detector_fp, status);
        CREATE INDEX IF NOT EXISTS tasks_lease_queue
            ON tasks(run_id, stage, status, available_at, task_id);
        CREATE INDEX IF NOT EXISTS tasks_stale_lease
            ON tasks(status, lease_expires_at);
        CREATE INDEX IF NOT EXISTS coverage_complete
            ON discovery_coverage(run_id, complete, capped);
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS catalog_events (
            library_id TEXT NOT NULL REFERENCES libraries(library_id) ON DELETE CASCADE,
            catalog_version TEXT NOT NULL,
            observed_on TEXT NOT NULL,
            event TEXT NOT NULL
                CHECK (event IN ('appeared', 'renamed', 'retained', 'retired', 'disappeared')),
            name TEXT NOT NULL,
            catalog_status TEXT NOT NULL,
            source TEXT NOT NULL,
            provenance TEXT NOT NULL,
            effective_on TEXT,
            note TEXT NOT NULL DEFAULT '',
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (library_id, catalog_version, observed_on, event)
        );

        CREATE INDEX IF NOT EXISTS catalog_events_history
            ON catalog_events(library_id, observed_on, catalog_version);
        """,
    ),
    (
        3,
        """
        CREATE TABLE IF NOT EXISTS run_lineage (
            successor_run_id TEXT PRIMARY KEY
                REFERENCES runs(run_id) ON DELETE CASCADE,
            predecessor_run_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            compatibility_sha256 TEXT NOT NULL UNIQUE,
            compatibility_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS task_inheritance (
            successor_task_id INTEGER PRIMARY KEY
                REFERENCES tasks(task_id) ON DELETE CASCADE,
            successor_run_id TEXT NOT NULL
                REFERENCES runs(run_id) ON DELETE CASCADE,
            predecessor_run_id TEXT NOT NULL,
            predecessor_task_id INTEGER NOT NULL,
            stage TEXT NOT NULL,
            task_key TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            result_sha256 TEXT NOT NULL,
            network_task_source_sha256 TEXT NOT NULL,
            source_policy TEXT NOT NULL
                CHECK (source_policy IN ('required', 'advisory')),
            inherited_request_count INTEGER NOT NULL
                CHECK (inherited_request_count >= 0),
            created_at TEXT NOT NULL,
            UNIQUE (successor_run_id, stage, task_key)
        );

        CREATE INDEX IF NOT EXISTS task_inheritance_predecessor
            ON task_inheritance(predecessor_run_id, predecessor_task_id);
        """,
    ),
    (
        4,
        """
        CREATE TABLE IF NOT EXISTS network_task_usage (
            run_id TEXT NOT NULL
                REFERENCES runs(run_id) ON DELETE CASCADE,
            task_id INTEGER NOT NULL
                REFERENCES tasks(task_id) ON DELETE CASCADE,
            attempt INTEGER NOT NULL CHECK (attempt > 0),
            source TEXT NOT NULL
                CHECK (source IN ('github-code-search', 'sourcegraph')),
            result_status TEXT NOT NULL
                CHECK (result_status IN ('complete', 'failed')),
            operation_count INTEGER NOT NULL
                CHECK (operation_count >= 0),
            request_attempt_count INTEGER NOT NULL
                CHECK (request_attempt_count >= 0),
            retry_count INTEGER NOT NULL
                CHECK (retry_count >= 0),
            rate_limited_attempts INTEGER NOT NULL
                CHECK (rate_limited_attempts >= 0),
            server_error_attempts INTEGER NOT NULL
                CHECK (server_error_attempts >= 0),
            network_error_attempts INTEGER NOT NULL
                CHECK (network_error_attempts >= 0),
            budget_rejections INTEGER NOT NULL
                CHECK (budget_rejections >= 0),
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (task_id, attempt),
            UNIQUE (run_id, task_id, attempt)
        );

        CREATE INDEX IF NOT EXISTS network_task_usage_run_source
            ON network_task_usage(run_id, source, task_id, attempt);
        """,
    ),
    (
        5,
        """
        CREATE TABLE IF NOT EXISTS scan_attempts (
            task_id TEXT NOT NULL
                REFERENCES tasks(task_id) ON DELETE CASCADE,
            attempt INTEGER NOT NULL CHECK (attempt > 0),
            run_id TEXT NOT NULL
                REFERENCES runs(run_id) ON DELETE CASCADE,
            repository_id TEXT NOT NULL
                REFERENCES repositories(node_id) ON DELETE CASCADE,
            task_key TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL
                CHECK (
                    length(payload_sha256) = 64
                    AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
            head_sha TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK (
                    status IN (
                        'running', 'complete', 'failed', 'interrupted'
                    )
                ),
            retryable INTEGER CHECK (retryable IN (0, 1)),
            error_code TEXT,
            error_detail TEXT,
            seconds REAL CHECK (seconds IS NULL OR seconds >= 0),
            current_tree_triage_seconds REAL
                CHECK (
                    current_tree_triage_seconds IS NULL
                    OR current_tree_triage_seconds >= 0
                ),
            history_dating_seconds REAL
                CHECK (
                    history_dating_seconds IS NULL
                    OR history_dating_seconds >= 0
                ),
            analysis_seconds REAL
                CHECK (analysis_seconds IS NULL OR analysis_seconds >= 0),
            git_subprocess_count INTEGER
                CHECK (git_subprocess_count IS NULL OR git_subprocess_count >= 0),
            network_clone_count INTEGER
                CHECK (network_clone_count IS NULL OR network_clone_count >= 0),
            network_fetch_count INTEGER
                CHECK (network_fetch_count IS NULL OR network_fetch_count >= 0),
            network_materialized_bytes INTEGER
                CHECK (
                    network_materialized_bytes IS NULL
                    OR network_materialized_bytes >= 0
                ),
            usage_complete INTEGER NOT NULL DEFAULT 0
                CHECK (usage_complete IN (0, 1)),
            started_at TEXT NOT NULL,
            finished_at TEXT,
            PRIMARY KEY (task_id, attempt),
            CHECK (
                usage_complete = 0
                OR (
                    seconds IS NOT NULL
                    AND current_tree_triage_seconds IS NOT NULL
                    AND history_dating_seconds IS NOT NULL
                    AND analysis_seconds IS NOT NULL
                    AND git_subprocess_count IS NOT NULL
                    AND network_clone_count IS NOT NULL
                    AND network_fetch_count IS NOT NULL
                    AND network_materialized_bytes IS NOT NULL
                )
            )
        );

        CREATE INDEX IF NOT EXISTS scan_attempts_run_status
            ON scan_attempts(run_id, status, task_id, attempt);
        CREATE INDEX IF NOT EXISTS scan_attempts_repository
            ON scan_attempts(repository_id, head_sha, task_id, attempt);
        """,
    ),
)


def _statements(script: str):
    """Yield complete SQLite statements, including future trigger bodies."""
    pending: list[str] = []
    for line in script.splitlines(keepends=True):
        pending.append(line)
        candidate = "".join(pending).strip()
        if candidate and sqlite3.complete_statement(candidate):
            yield candidate
            pending = []
    remainder = "".join(pending).strip()
    if remainder:
        raise RuntimeError("incomplete SQL in state migration")


def current_version(connection: sqlite3.Connection) -> int:
    """Return the installed schema version, including a pristine database."""
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if row is None:
        return 0
    installed = connection.execute(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
    ).fetchone()
    return int(installed[0])


def pending_versions(connection: sqlite3.Connection) -> tuple[int, ...]:
    installed = current_version(connection)
    return tuple(version for version, _ in MIGRATIONS if version > installed)


def apply_migrations(
    connection: sqlite3.Connection,
    *,
    now: Callable[[], str],
    before_migration: Callable[[int, int], None] | None = None,
) -> int:
    """Apply all pending migrations atomically and return the final version.

    A migration record and ``PRAGMA user_version`` are committed in the same
    transaction as its DDL.  Reopening after a crash can therefore safely call
    this function again.
    """
    installed = current_version(connection)
    for version, sql in MIGRATIONS:
        if version <= installed:
            continue
        if version != installed + 1:
            raise RuntimeError(
                f"non-contiguous state migration: installed={installed}, next={version}"
            )
        if before_migration is not None:
            before_migration(installed, version)
        try:
            connection.execute("BEGIN IMMEDIATE")
            # sqlite3.Connection.executescript() issues an implicit COMMIT before
            # running its script.  Execute complete statements individually so
            # the schema and migration marker really share one transaction.
            for statement in _statements(sql):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, now()),
            )
            connection.execute(f"PRAGMA user_version = {version}")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        installed = version
    if installed != SCHEMA_VERSION:
        raise RuntimeError(
            f"state schema mismatch: installed={installed}, expected={SCHEMA_VERSION}"
        )
    return installed
