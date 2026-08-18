"""Read-only planning and granular invalidation for the REQ-14 pipeline."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
import statistics
from typing import Any, Mapping

from . import config
from .catalog import CATALOG, CATALOG_VERSION
from .discovery.query_plan import query_packs, signal_specs
from .fingerprints import FingerprintManifest, build_manifest, invalidation_plan
from .nvpl_components import override_policy_sha256


PLANNER_VERSION = 1
SCANNER_ENGINE_VERSION = 10
DISCOVERY_ENGINE_VERSION = 8
DATING_ENGINE_VERSION = 3
AI_ENGINE_VERSION = 2
AGGREGATION_ENGINE_VERSION = 4
PUBLICATION_SCHEMA_VERSION = 3
OUTLIER_LIMIT = 10

# The planner cannot know compressed wire sizes before making a request.  These
# constants are deliberately visible, conservative planning assumptions rather
# than measurements.  Final run metrics must replace them with actual bytes.
SEARCH_RESPONSE_BYTES_PER_QUERY = 512 * 1024
GRAPHQL_RESPONSE_BYTES_PER_REPOSITORY = 4 * 1024
# The frozen 105-repository cold corpus materialized 4.99 GB, or 47.5 MB per
# repository. Round up: the older 16 MiB placeholder materially understated a
# cold portfolio before repository-specific GitHub diskUsage is available.
DEFAULT_GIT_TRANSFER_BYTES_PER_REPOSITORY = 50 * 1024 * 1024


def _scanner_semantic_source_sha256() -> str:
    """Fingerprint shared detector implementations, not only declarations.

    A manual engine integer is useful for communicating a semantic epoch, but
    it cannot make a behavior edit self-invalidating. Hashing the shared
    classification implementations makes every such edit fail toward bounded
    re-evaluation even if a maintainer forgets to bump the readable version.
    """
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parent
    for name in (
        "scan.py",
        "scanner_v2.py",
        "triage.py",
        "evidence_content.py",
        "repo_cache.py",
    ):
        payload = (root / name).read_bytes()
        encoded_name = name.encode()
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _read_only_sqlite_uri(state_path: Path) -> str:
    """Open a clean WAL database read-only without creating SHM companions."""
    resolved = state_path.resolve()
    uri = resolved.as_uri() + "?mode=ro"
    # A closed/checkpointed WAL database has no WAL or SHM companions. SQLite
    # otherwise tries to create SHM even in mode=ro; immutable avoids that
    # false failure. A live WAL must remain non-immutable so committed WAL rows
    # are visible to the plan.
    if not Path(str(resolved) + "-wal").exists():
        uri += "&immutable=1"
    return uri


def _regex(value):
    return {"pattern": value.pattern, "flags": value.flags}


def _library_declaration(lib: Mapping[str, Any]) -> dict:
    discovery_keys = (
        "token", "header", "cpp_headers", "header_prefixes",
        "import_namespace", "import_namespaces", "pip_pattern",
        "discovery_tokens", "targeted_build_discovery_anchors",
        "language", "family", "repository_exceptions",
    )
    detector_keys = (
        "token", "header", "cpp_headers", "header_prefixes",
        "import_namespace", "import_namespaces", "strict_import",
        "allow_qualified_call",
        "direct_regexes", "pip_pattern", "language", "family",
        "components", "optional_backend_files", "build_signals",
        "direct_only", "evidence_contract", "targeted_build_signals",
        "targeted_build_discovery_anchors",
    )
    return {
        "discovery": {
            "engine": DISCOVERY_ENGINE_VERSION,
            **{key: lib.get(key) for key in discovery_keys if key in lib},
        },
        "detector": {
            "engine": SCANNER_ENGINE_VERSION,
            **{key: lib.get(key) for key in detector_keys if key in lib},
        },
        "citation": {
            "query": lib.get("citation_query"),
            "cooccur": lib.get("citation_cooccur", ()),
            "tier": lib.get("citation_tier"),
            "confidence": lib.get("citation_confidence"),
        },
        "presentation": {
            "name": lib["name"],
            "tier": lib["tier"],
            "description": lib["description"],
            "coverage": lib.get(
                "classification_coverage",
                ("confirmed", "bundled", "targeted"),
            ),
            "not_evaluated": lib.get("not_evaluated_classes", ()),
            "rollup_to": lib.get("rollup_to"),
        },
        "release": {
            "released_on": lib["released_on"],
            "released_confidence": lib["released_confidence"],
        },
    }


def current_fingerprints(libraries=None) -> FingerprintManifest:
    libraries = list(libraries or config.LIBRARIES)
    semantic_source = _scanner_semantic_source_sha256()
    declarations = {}
    for library in libraries:
        declaration = _library_declaration(library)
        declaration["detector"]["shared_source_sha256"] = semantic_source
        declarations[library["id"]] = declaration
    return build_manifest(
        declarations,
        dating_semantics={
            "engine": DATING_ENGINE_VERSION,
            "pickaxe": "literal-then-regex",
            "rename_aware": True,
            "release_clamp": "derived-only",
        },
        ai_semantics={
            "engine": AI_ENGINE_VERSION,
            "signals": [
                (label, kind, _regex(pattern))
                for label, kind, pattern in config.AI_SIGNALS
            ],
            "config_files": _regex(config.AI_CONFIG_FILE_RE),
        },
        filter_profiles={
            "shared": {
                "vendor": _regex(config.VENDOR_PATH_RE),
                "environment": _regex(config.ENV_DUMP_PATH_RE),
                "docs": _regex(config.DOC_SKILL_PATH_RE),
                "excluded_orgs": config.EXCLUDED_ORGS,
                "excluded_prefixes": config.EXCLUDED_ORG_PREFIXES,
                "excluded_names": config.EXCLUDED_NAME_SUBSTR,
                "excluded_repositories": config.EXCLUDED_REPOS,
            },
            "nvpl": {
                "parents": config.NVPL_VENDOR_PARENTS,
                "names": config.NVPL_VENDOR_NAME_SUBSTR,
            },
        },
        aggregation_semantics={
            "engine": AGGREGATION_ENGINE_VERSION,
            "family_rollups": "unique-repository",
            "catalog_version": CATALOG_VERSION,
            "nvpl_component_bucket_overrides": override_policy_sha256(),
            "partial_cohort": (
                "current-counts-with-stale-v1-boundary"
            ),
        },
        publication_semantics={
            "schema": PUBLICATION_SCHEMA_VERSION,
            "sharded": True,
            "manifest_last": True,
            "partial_scope": (
                "explicit-selected-excluded-null-counts"
            ),
        },
    )


def _prior_manifest_from_state(state_path: Path) -> FingerprintManifest | None:
    if not state_path.exists():
        return None
    import sqlite3

    connection = sqlite3.connect(_read_only_sqlite_uri(state_path), uri=True)
    try:
        row = connection.execute(
            """
            SELECT fingerprints_json FROM runs
            WHERE status='complete'
            ORDER BY finished_at DESC, created_at DESC
            LIMIT 1
            """
        ).fetchone()
    except sqlite3.DatabaseError:
        return None
    finally:
        connection.close()
    if not row:
        return None
    try:
        return FingerprintManifest.from_dict(json.loads(row[0]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _local_counts(
    state_path: Path,
    data_dir: Path,
    *,
    current_ai_fp: str | None = None,
) -> dict:
    counts = {
        "known_repositories": 0,
        "active_candidates": 0,
        "reusable_scan_results": 0,
        "nonreusable_candidate_repositories": 0,
        "analysis_only_repositories": 0,
        "locally_planned_scan_repositories": 0,
        "positive_repositories": 0,
        "legacy_published_repositories": 0,
    }
    current_path = data_dir / "current.json"
    if current_path.exists():
        try:
            current = json.loads(current_path.read_text())
            counts["legacy_published_repositories"] = len(current.get("repos", ()))
        except (OSError, ValueError, TypeError):
            pass
    if not state_path.exists():
        return counts
    import sqlite3

    connection = sqlite3.connect(_read_only_sqlite_uri(state_path), uri=True)
    try:
        counts["known_repositories"] = connection.execute(
            "SELECT COUNT(*) FROM repositories"
        ).fetchone()[0]
        counts["active_candidates"] = connection.execute(
            "SELECT COUNT(*) FROM candidates WHERE state='active'"
        ).fetchone()[0]
        counts["reusable_scan_results"] = connection.execute(
            "SELECT COUNT(*) FROM scan_results WHERE status='clean'"
        ).fetchone()[0]
        counts["nonreusable_candidate_repositories"] = connection.execute(
            """
            SELECT COUNT(DISTINCT r.node_id)
            FROM repositories r
            JOIN candidates c
              ON c.repository_id=r.node_id AND c.state='active'
            JOIN libraries l
              ON l.library_id=c.library_id AND l.active=1
            WHERE r.visibility='public' AND r.is_fork=0 AND r.is_archived=0
              AND r.head_sha IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM scan_results s
                  WHERE s.repository_id=r.node_id
                    AND s.library_id=c.library_id
                    AND s.head_sha=r.head_sha
                    AND s.detector_fp=l.detector_fp
                    AND s.status='clean'
              )
            """
        ).fetchone()[0]
        if current_ai_fp:
            counts["analysis_only_repositories"] = connection.execute(
                """
                SELECT COUNT(DISTINCT r.node_id)
                FROM repositories r
                JOIN scan_results s
                  ON s.repository_id=r.node_id
                 AND s.head_sha=r.head_sha
                 AND s.status='clean'
                 AND s.classification!='rejected'
                JOIN libraries l
                  ON l.library_id=s.library_id
                 AND l.detector_fp=s.detector_fp
                 AND l.active=1
                WHERE r.visibility='public'
                  AND r.is_fork=0 AND r.is_archived=0
                  AND NOT EXISTS (
                      SELECT 1 FROM repo_analysis a
                      WHERE a.repository_id=r.node_id
                        AND a.head_sha=r.head_sha
                        AND a.ai_fp=?
                        AND a.status='clean'
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM candidates c2
                      JOIN libraries l2
                        ON l2.library_id=c2.library_id AND l2.active=1
                      WHERE c2.repository_id=r.node_id
                        AND c2.state='active'
                        AND NOT EXISTS (
                            SELECT 1 FROM scan_results s2
                            WHERE s2.repository_id=r.node_id
                              AND s2.library_id=c2.library_id
                              AND s2.head_sha=r.head_sha
                              AND s2.detector_fp=l2.detector_fp
                              AND s2.status='clean'
                        )
                  )
                """,
                (current_ai_fp,),
            ).fetchone()[0]
        counts["locally_planned_scan_repositories"] = (
            counts["nonreusable_candidate_repositories"]
            + counts["analysis_only_repositories"]
        )
        counts["positive_repositories"] = connection.execute(
            """
            SELECT COUNT(DISTINCT s.repository_id)
            FROM scan_results s
            JOIN repositories r
              ON r.node_id=s.repository_id AND r.head_sha=s.head_sha
            JOIN libraries l
              ON l.library_id=s.library_id AND l.detector_fp=s.detector_fp
            WHERE s.status='clean' AND s.classification!='rejected'
              AND r.visibility='public' AND r.is_fork=0 AND r.is_archived=0
            """
        ).fetchone()[0]
    except sqlite3.DatabaseError:
        pass
    finally:
        connection.close()
    return counts


def _local_observability(state_path: Path) -> dict[str, Any]:
    """Read public-only size/query evidence for deterministic plan outliers."""
    empty = {
        "repository_sizes": (),
        "repositories": (),
        "queries": (),
        "repository_count": 0,
        "unknown_repository_size_count": 0,
    }
    if not state_path.exists():
        return empty
    import sqlite3

    connection = sqlite3.connect(_read_only_sqlite_uri(state_path), uri=True)
    connection.row_factory = sqlite3.Row
    try:
        repository_rows = connection.execute(
            """
            SELECT r.node_id, r.full_name, r.metadata_json,
                   COUNT(c.candidate_id) AS candidate_count,
                   COUNT(DISTINCT c.library_id) AS library_count
            FROM repositories r
            LEFT JOIN candidates c
              ON c.repository_id=r.node_id AND c.state='active'
            WHERE r.visibility='public' AND r.is_fork=0 AND r.is_archived=0
            GROUP BY r.node_id, r.full_name, r.metadata_json
            """
        ).fetchall()
        query_rows = connection.execute(
            """
            SELECT c.source, c.library_id, c.query_fp, c.signal,
                   COUNT(DISTINCT c.repository_id) AS candidate_count
            FROM candidates c
            JOIN repositories r ON r.node_id=c.repository_id
            WHERE c.state='active' AND r.visibility='public'
              AND r.is_fork=0 AND r.is_archived=0
            GROUP BY c.source, c.library_id, c.query_fp, c.signal
            """
        ).fetchall()
    except sqlite3.DatabaseError:
        return empty
    finally:
        connection.close()

    repositories = []
    repository_sizes = []
    unknown_repository_size_count = 0
    for row in repository_rows:
        try:
            metadata = json.loads(row["metadata_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            metadata = {}
        raw_disk_usage = metadata.get("disk_usage_kb")
        try:
            disk_usage_kb = (
                None
                if raw_disk_usage is None or isinstance(raw_disk_usage, bool)
                else int(raw_disk_usage)
            )
        except (TypeError, ValueError):
            disk_usage_kb = None
        if disk_usage_kb is not None and disk_usage_kb < 0:
            disk_usage_kb = None
        estimated_transfer = (
            None if disk_usage_kb is None else disk_usage_kb * 1024
        )
        if estimated_transfer is None:
            unknown_repository_size_count += 1
        elif estimated_transfer:
            repository_sizes.append(estimated_transfer)
        repositories.append({
            "full_name": str(row["full_name"]),
            "estimated_git_transfer_bytes_upper_bound": estimated_transfer,
            "active_candidate_count": int(row["candidate_count"] or 0),
            "active_library_count": int(row["library_count"] or 0),
            "size_basis": (
                "GitHub diskUsage metadata"
                if estimated_transfer is not None
                else "size unavailable"
            ),
        })
    repositories.sort(
        key=lambda item: (
            -(item["estimated_git_transfer_bytes_upper_bound"] or 0),
            -item["active_candidate_count"],
            item["full_name"].casefold(),
        )
    )

    queries = [{
        "source": str(row["source"]),
        "library_id": str(row["library_id"]),
        "query_fingerprint": str(row["query_fp"]),
        "signal": str(row["signal"]),
        "observed_active_candidates": int(row["candidate_count"] or 0),
        "estimated_response_bytes": (
            int(row["candidate_count"] or 0) * 768
        ),
        "size_basis": "768 encoded bytes per observed candidate",
    } for row in query_rows]
    queries.sort(
        key=lambda item: (
            -item["observed_active_candidates"],
            item["source"],
            item["library_id"],
            item["query_fingerprint"],
            item["signal"],
        )
    )
    return {
        "repository_sizes": tuple(repository_sizes),
        "repositories": tuple(repositories[:OUTLIER_LIMIT]),
        "queries": tuple(queries[:OUTLIER_LIMIT]),
        "repository_count": len(repository_rows),
        "unknown_repository_size_count": unknown_repository_size_count,
    }


@dataclasses.dataclass(frozen=True)
class RunPlan:
    mode: str
    cold_state: bool
    fingerprints: FingerprintManifest
    invalidation: Any
    local_counts: Mapping[str, int]
    estimated_scans: int
    estimated_graphql_requests: int
    estimated_initial_graphql_requests: int
    estimated_final_visibility_graphql_requests: int
    estimated_final_visibility_minutes: int
    estimated_github_search_requests_floor: int
    estimated_sourcegraph_requests: int
    estimated_network_bytes: Mapping[str, int]
    estimated_wall_minutes: int
    unknown_repository_size_count: int
    outliers: Mapping[str, tuple[Mapping[str, Any], ...]]
    estimate_assumptions: tuple[str, ...]
    requires_full_confirmation: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        invalidation = dataclasses.asdict(self.invalidation)
        for key, value in list(invalidation.items()):
            if isinstance(value, (set, frozenset)):
                invalidation[key] = sorted(value)
        return {
            "mode": self.mode,
            "cold_state": self.cold_state,
            "fingerprints": self.fingerprints.as_dict(),
            "invalidation": invalidation,
            "local_counts": dict(self.local_counts),
            "estimates": {
                "scans": self.estimated_scans,
                "graphql_requests": self.estimated_graphql_requests,
                "initial_graphql_requests": (
                    self.estimated_initial_graphql_requests
                ),
                "final_visibility_graphql_requests": (
                    self.estimated_final_visibility_graphql_requests
                ),
                "final_visibility_minutes": (
                    self.estimated_final_visibility_minutes
                ),
                "final_visibility_max_age_minutes": 120,
                "github_search_requests_floor": self.estimated_github_search_requests_floor,
                "sourcegraph_requests": self.estimated_sourcegraph_requests,
                "network_bytes": dict(self.estimated_network_bytes),
                "wall_minutes": self.estimated_wall_minutes,
                "repositories_with_unknown_size": (
                    self.unknown_repository_size_count
                ),
            },
            "outliers": {
                key: [dict(item) for item in values]
                for key, values in self.outliers.items()
            },
            "estimate_assumptions": list(self.estimate_assumptions),
            "requires_full_confirmation": self.requires_full_confirmation,
            "reasons": list(self.reasons),
        }


def build_plan(
    *,
    mode="refresh",
    state_path=".state/collector.sqlite3",
    data_dir="data",
    libraries=None,
    weekly_scan_budget=2_000,
    max_graphql_points=2_500,
    min_graphql_remaining=2_500,
    assumed_graphql_quota=5_000,
) -> RunPlan:
    """Build a plan using only local files and a read-only SQLite connection."""
    libraries = list(libraries or config.LIBRARIES)
    state_path = Path(state_path).resolve()
    data_dir = Path(data_dir).resolve()
    current = current_fingerprints(libraries)
    previous = _prior_manifest_from_state(state_path)
    invalidation = invalidation_plan(
        previous,
        current,
        profile_libraries={
            "shared": [lib["id"] for lib in libraries],
            "nvpl": ["nvpl"],
        },
    )
    counts = _local_counts(
        state_path,
        data_dir,
        current_ai_fp=current.ai,
    )
    observed = _local_observability(state_path)
    known = max(
        counts["known_repositories"],
        counts["legacy_published_repositories"],
    )
    cold = previous is None
    # The legacy release covers only the original small catalog. Before the
    # first all-portfolio discovery epoch, its 3.8k rows are a lower bound, not
    # a credible estimate for 49 official products plus components. Use the
    # research spike's 30k planning envelope until production state replaces
    # uncertainty with an observed candidate count.
    cold_portfolio_envelope = 30_000 if len(libraries) >= 40 else known
    planning_known = max(known, cold_portfolio_envelope) if cold else known
    # Cold state has no trustworthy HEAD/fingerprint reuse.  Otherwise the
    # estimate is bounded by known candidates affected by detector changes;
    # discovery can add work and is reported separately at runtime.
    shared_reanalysis = (
        invalidation.redate_all_positives
        or invalidation.reanalyze_all_publishable
    )
    estimated_scans = (
        planning_known
        if cold or invalidation.scan
        else counts["positive_repositories"]
        if shared_reanalysis
        else counts["locally_planned_scan_repositories"]
    )
    github_floor = sum(len(query_packs(lib)) for lib in libraries)
    sourcegraph = github_floor
    initial_graphql = (planning_known + 49) // 50
    final_visibility_graphql = initial_graphql
    graphql = initial_graphql + final_visibility_graphql
    observed_sizes = list(observed["repository_sizes"])
    typical_git_bytes = (
        max(1, round(statistics.median(observed_sizes)))
        if observed_sizes
        else DEFAULT_GIT_TRANSFER_BYTES_PER_REPOSITORY
    )
    largest_observed = sorted(observed_sizes, reverse=True)
    sized_count = min(estimated_scans, len(largest_observed))
    estimated_git_bytes = (
        sum(largest_observed[:sized_count])
        + max(0, estimated_scans - sized_count) * typical_git_bytes
    )
    estimated_network_bytes = {
        "sourcegraph_response_floor": (
            sourcegraph * SEARCH_RESPONSE_BYTES_PER_QUERY
        ),
        "github_search_response_floor": (
            github_floor * SEARCH_RESPONSE_BYTES_PER_QUERY
        ),
        "github_graphql_response": (
            planning_known * GRAPHQL_RESPONSE_BYTES_PER_REPOSITORY * 2
        ),
        "git_transfer_upper_estimate": estimated_git_bytes,
    }
    estimated_network_bytes["total"] = sum(estimated_network_bytes.values())

    planned_query_groups = [{
        "library_id": lib["id"],
        "declared_signal_lanes": len(signal_specs(lib)),
        "planned_query_packs": len(query_packs(lib)),
        # Retained compatibility name: this value has always represented
        # planned network queries, which are query packs after REQ-14 Phase 2.
        "declared_signal_queries": len(query_packs(lib)),
        "estimated_response_bytes_floor": (
            len(query_packs(lib))
            * SEARCH_RESPONSE_BYTES_PER_QUERY
            * 2
        ),
        "size_basis": (
            "one Sourcegraph and one GitHub response per deterministic "
            "library-scoped query pack"
        ),
    } for lib in libraries]
    planned_query_groups.sort(
        key=lambda item: (
            -item["declared_signal_queries"],
            item["library_id"],
        )
    )
    # Frozen 105-repository Mac benchmark, 2026-07-28: the exact final scanner
    # source sustained 2,854.68 repos/hour at 14 workers on the mature lane
    # (2,991.88/hour on an immediate repeat) and 2,533.79/hour at the
    # six-worker normal setting. These are scanner rates over a pinned local
    # public corpus, not end-to-end production collection claims. Round down
    # below the slower comparable measured rate so the planner retains margin.
    # Cold state has cold economics even when the operator asks for the weekly
    # view; it must not be shown the warm rate.
    cold_economics = cold or mode == "reconcile"
    throughput = 2_800 if cold_economics else 2_500
    # Non-scan time is an explicit planning model, not a measured end-to-end
    # production claim: paced GitHub search, Sourcegraph latency, GraphQL
    # batching, and a fixed publication/citation/checkpoint allowance.
    final_visibility_seconds = final_visibility_graphql * 4.276
    wall = round(
        (estimated_scans / throughput) * 60
        + github_floor * 0.12
        + sourcegraph * 0.25
        + initial_graphql * 0.05
        + final_visibility_seconds / 60
        + 15
    )
    unknown_repository_size_count = (
        observed["unknown_repository_size_count"]
        + max(0, planning_known - observed["repository_count"])
    )
    reasons = []
    if cold:
        reasons.append("no completed V2 fingerprint state; cold reconciliation required")
        if planning_known > known:
            reasons.append(
                "portfolio expansion is unmeasured; using %d-candidate planning envelope"
                % planning_known
            )
    if estimated_scans > weekly_scan_budget and mode == "refresh":
        reasons.append(
            "planned scans exceed weekly budget (%d > %d)"
            % (estimated_scans, weekly_scan_budget)
        )
    if graphql > max_graphql_points:
        reasons.append(
            "two-pass GraphQL plan exceeds point budget (%d > %d)"
            % (graphql, max_graphql_points)
        )
    projected_graphql_remaining = assumed_graphql_quota - graphql
    if projected_graphql_remaining < min_graphql_remaining:
        reasons.append(
            "two-pass GraphQL plan would cross remaining-quota reserve "
            "(%d < %d)"
            % (projected_graphql_remaining, min_graphql_remaining)
        )
    if final_visibility_seconds > 2 * 60 * 60:
        reasons.append(
            "serial final visibility pass would exceed the 120-minute "
            "install freshness limit (%.1f minutes)"
            % (final_visibility_seconds / 60)
        )
    return RunPlan(
        mode=mode,
        cold_state=cold,
        fingerprints=current,
        invalidation=invalidation,
        local_counts=counts,
        estimated_scans=estimated_scans,
        estimated_graphql_requests=graphql,
        estimated_initial_graphql_requests=initial_graphql,
        estimated_final_visibility_graphql_requests=(
            final_visibility_graphql
        ),
        estimated_final_visibility_minutes=max(
            0, round(final_visibility_seconds / 60)
        ),
        estimated_github_search_requests_floor=github_floor,
        estimated_sourcegraph_requests=sourcegraph,
        estimated_network_bytes=estimated_network_bytes,
        estimated_wall_minutes=max(1, wall),
        unknown_repository_size_count=unknown_repository_size_count,
        outliers={
            "repositories": observed["repositories"],
            "observed_queries": observed["queries"],
            "planned_query_groups": tuple(
                planned_query_groups[:OUTLIER_LIMIT]
            ),
        },
        estimate_assumptions=(
            "search byte estimates assume 512 KiB per unpartitioned query; "
            "partitioning and retries can increase actual bytes",
            (
                "GraphQL request and byte estimates include an initial "
                "metadata pass and a final stable-ID visibility pass at "
                "50 repositories per batch and 4 KiB per repository/pass"
            ),
            (
                "GraphQL reserve projection assumes %d points available "
                "and one point per planned batch"
                % assumed_graphql_quota
            ),
            (
                "final visibility duration uses the validated 4.276-second "
                "serial latency per 50-repository GraphQL batch and must "
                "remain within the 120-minute install freshness limit"
            ),
            (
                "Git transfer estimate uses the largest observed GitHub diskUsage "
                "values, then a median fallback"
                if observed_sizes
                else (
                    "Git transfer estimate uses a 50 MiB per-repository cold "
                    "fallback from the frozen 105-repository Mac corpus"
                )
            ),
            "all byte estimates are planning values; completed-run metrics are authoritative",
            (
                "scanner wall estimate uses the measured Mac floor of "
                f"{throughput:,} repositories/hour for "
                f"{'cold' if cold_economics else 'warm'} work"
            ),
            (
                "non-scan wall estimate models paced GitHub search at 7.2s/base "
                "query, Sourcegraph at 15s/base query, initial GraphQL at "
                "3s/batch, final visibility GraphQL at 4.276s/batch, "
                "plus 15 minutes for citation/publication/checkpoint work; "
                "recursive partitions and production outliers can increase it"
            ),
        ),
        # The plan reports whether a full run needs an explicit attended
        # confirmation regardless of the selected view.  The reconcile command
        # enforces the same contract with --confirm-full.
        requires_full_confirmation=bool(cold or reasons),
        reasons=tuple(reasons),
    )


def catalog_pending_cards():
    """Return portfolio records that intentionally have no detector metric."""
    return [
        item for item in CATALOG
        if item["trackability"] != "direct_code"
    ]
