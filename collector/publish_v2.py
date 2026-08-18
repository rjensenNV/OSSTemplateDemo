"""Deterministic, manifest-driven V2 publication.

This module is deliberately independent of collection.  It accepts the four
already-generated V1 documents, builds immutable content-addressed artifacts
under a staging directory, validates them, and changes the live manifest only
after every referenced artifact is in place.

The stateful pipeline calls ``stage_v2``/``publish_v2`` with an already
validated state materialization. ``publish_from_v1`` remains a pure migration
and parity helper, but its former standalone mutation command is retired.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "2.0"
# Exclusive publication limit: every non-manifest artifact must encode to
# strictly fewer bytes than this value.
TARGET_ARTIFACT_BYTES = 4_000_000
HARD_ARTIFACT_BYTES = 5 * 1024 * 1024
MAX_MANIFEST_BYTES = 250 * 1024
CLASSIFICATIONS = ("confirmed", "bundled", "targeted")
STATE_VISIBILITY_ATTESTATION = "v2_graphql_public_only_state_boundary"
LEGACY_VISIBILITY_ATTESTATION = "legacy_v1_public_snapshot_migration"
_UNUSED_REPOSITORY_FIELDS = frozenset(("owner_type", "topics", "license"))
_PRIVATE_MARKER_FIELDS = frozenset(
    ("private", "is_private", "visibility_excluded")
)
_VISIBILITY_SOURCE_FIELDS = frozenset(
    ("visibility", "is_public", *_PRIVATE_MARKER_FIELDS)
)
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_ROWS_SENTINEL = "__CXIT_V2_ROWS_SENTINEL_4c55f673__"
_CSV_FORMULA_PREFIX = re.compile(r"^[\x00-\x20]*[=+\-@]")


class PublicationError(RuntimeError):
    """Raised before a live manifest is changed."""


def _publication_date(value: object, label: str) -> datetime.date:
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError) as exc:
        raise PublicationError(f"{label} must contain an ISO publication date") from exc


def _within_last_week(value: object, as_of: datetime.date) -> bool:
    """Return true for a complete ISO date in the seven calendar days ending as_of."""
    if not isinstance(value, str) or len(value) < 10:
        return False
    try:
        observed = datetime.date.fromisoformat(value[:10])
    except ValueError:
        return False
    return as_of - datetime.timedelta(days=7) < observed <= as_of


def _has_non_public_marker(repo: Mapping[str, Any]) -> bool:
    """Return whether any explicit visibility alias fails closed.

    Old collector payloads used several names for the same boundary.  False
    private flags are harmless migration residue, but a truthy or malformed
    private marker is not safe to reinterpret.  Likewise, an ``is_public``
    alias must be the actual boolean ``True`` when supplied.
    """
    for field in _PRIVATE_MARKER_FIELDS:
        if field in repo and repo.get(field) not in (None, False, 0, ""):
            return True
    if "is_public" in repo and repo.get("is_public") is not True:
        return True
    return False


def canonical_json(value: Any) -> bytes:
    """Return the one canonical JSON encoding used for hashes and byte limits."""
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _release_identity(manifest: Mapping[str, Any]) -> str:
    """Hash every public manifest semantic except the identity itself."""
    semantic = dict(manifest)
    release = semantic.get("release")
    if not isinstance(release, Mapping):
        raise PublicationError("release metadata must be an object")
    semantic["release"] = {
        key: value for key, value in release.items() if key != "id"
    }
    return _sha256(canonical_json(semantic))[:20]


def _descriptor(path: str, data: bytes, rows: int | None, media_type: str) -> dict:
    result = {
        "path": path,
        "bytes": len(data),
        "sha256": _sha256(data),
        "media_type": media_type,
    }
    if rows is not None:
        result["rows"] = rows
    return result


def _content_path(prefix: str, ordinal: int | None, data: bytes, suffix: str) -> str:
    digest = _sha256(data)[:16]
    if ordinal is None:
        return f"{prefix}-{digest}.{suffix}"
    return f"{prefix}/part-{ordinal:03d}-{digest}.{suffix}"


def _write(root: Path, path: str, data: bytes) -> None:
    destination = root / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def _validate_library_id(library_id: object) -> str:
    if not isinstance(library_id, str) or not _SAFE_ID.fullmatch(library_id):
        raise PublicationError("library IDs must be non-empty filesystem-safe strings")
    return library_id


def _classification_coverage(library: Mapping[str, Any]) -> dict[str, str]:
    supplied = library.get("classification_coverage")
    if supplied is None:
        return {name: "evaluated" for name in CLASSIFICATIONS}
    if not isinstance(supplied, Mapping):
        raise PublicationError("classification_coverage must be an object")
    result = {}
    for name in CLASSIFICATIONS:
        value = supplied.get(name, "evaluated")
        if value is True:
            value = "evaluated"
        elif value is False:
            value = "not_evaluated"
        if value not in ("evaluated", "not_evaluated"):
            raise PublicationError(
                "classification_coverage values must be evaluated or not_evaluated"
            )
        result[name] = value
    return result


def _is_carried_forward_entry(entry: Mapping[str, Any]) -> bool:
    carried = entry.get("carried_forward") is True
    if not carried:
        return False
    if (
        entry.get("stale") is not True
        or not isinstance(entry.get("as_of"), str)
        or not entry.get("as_of")
    ):
        raise PublicationError(
            "carried-forward evidence requires stale as-of provenance"
        )
    return True


def _assert_publishable_source(
    repositories: Sequence[Mapping[str, Any]],
) -> str:
    """Reject explicit non-public state without repeating a private repo name.

    The migration input predates a persisted visibility field, so absence is
    accepted only at this V1 boundary.  Every V2 row is stamped PUBLIC and the
    validator requires an honest source-specific attestation.
    """
    names: set[str] = set()
    all_explicit_public = True
    for repo in repositories:
        name = repo.get("full_name")
        if not isinstance(name, str) or not name or name in names:
            raise PublicationError("source repositories require unique non-empty full_name")
        names.add(name)
        visibility = repo.get("visibility")
        if visibility is None:
            all_explicit_public = False
        if (
            _has_non_public_marker(repo)
            or (visibility is not None and str(visibility).upper() != "PUBLIC")
        ):
            raise PublicationError(
                "source contains a repository that is not explicitly publishable"
            )
    return (
        STATE_VISIBILITY_ATTESTATION
        if all_explicit_public
        else LEGACY_VISIBILITY_ATTESTATION
    )


def _effective_entry(
    repo: Mapping[str, Any], library: Mapping[str, Any]
) -> dict[str, Any] | None:
    library_id = library["id"]
    entries = repo.get("libraries") or []
    if not isinstance(entries, list):
        raise PublicationError("repository libraries must be a list")
    for entry in entries:
        if entry.get("library_id") == library_id:
            return dict(entry)
    parent_id = library.get("parent_id")
    # The committed V1 component cards predate ``projected_from_parent`` and
    # identify their projected children only with ``is_component``.  Treat an
    # explicit flag as authoritative for state-built V2 cards, but preserve
    # the legacy projection when that flag is absent.
    projected_from_parent = library.get("projected_from_parent")
    if projected_from_parent is None:
        projected_from_parent = library.get("is_component", False)
    if not parent_id or not projected_from_parent:
        return None

    label = library.get("component_label")
    for entry in entries:
        if entry.get("library_id") != parent_id:
            continue
        classification = entry.get("classification")
        operators = entry.get("operators") or []
        component_map = entry.get("component_detail")
        # Match the existing aggregate projection exactly.  Confirmed
        # membership is precise when component_detail exists; operators on a
        # confirmed parent can also contain build-only component labels.
        if classification == "confirmed":
            is_member = (
                label in component_map
                if component_map
                else label in operators
            )
        else:
            is_member = label in operators
        if not is_member:
            continue
        component = (component_map or {}).get(label, {})
        projected = dict(entry)
        projected["library_id"] = library_id
        projected["operators"] = [label]
        if isinstance(component, Mapping):
            for field in (
                "first_integration",
                "first_integration_commit",
                "ai_on_integration_commit",
                "ai_on_integration_agents",
            ):
                if component.get(field) is not None:
                    projected[field] = component[field]
        first_date = projected.get("first_integration")
        released_on = library.get("released_on")
        if first_date and released_on and str(first_date)[:7] < str(released_on):
            projected["first_integration"] = None
        projected.pop("component_detail", None)
        return projected
    return None


def _library_repo_row(
    repo: Mapping[str, Any], entry: Mapping[str, Any]
) -> dict[str, Any]:
    row = {
        key: value
        for key, value in repo.items()
        if key
        not in (
            "libraries",
            *_VISIBILITY_SOURCE_FIELDS,
            *_UNUSED_REPOSITORY_FIELDS,
        )
    }
    row["visibility"] = "PUBLIC"
    row["libraries"] = [dict(entry)]
    return row


def _export_repo_row(repo: Mapping[str, Any]) -> dict[str, Any]:
    row = {
        key: value
        for key, value in repo.items()
        if key
        not in (
            *_VISIBILITY_SOURCE_FIELDS,
            *_UNUSED_REPOSITORY_FIELDS,
        )
    }
    row["visibility"] = "PUBLIC"
    return row


def _json_row_frame(base: Mapping[str, Any]) -> tuple[bytes, bytes]:
    skeleton = dict(base)
    skeleton["rows"] = _ROWS_SENTINEL
    encoded = canonical_json(skeleton)
    marker = json.dumps(_ROWS_SENTINEL).encode("ascii")
    if encoded.count(marker) != 1:
        raise PublicationError("internal JSON shard framing error")
    prefix, suffix = encoded.split(marker)
    return prefix + b"[", b"]" + suffix


def _pack_json_rows(
    base: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
    target_bytes: int,
) -> list[tuple[bytes, int]]:
    """Pack rows in one pass using their exact final encoded byte size."""
    prefix, suffix = _json_row_frame(base)
    fixed = len(prefix) + len(suffix)
    if fixed >= target_bytes:
        raise PublicationError("artifact envelope exceeds the target byte limit")

    parts: list[tuple[bytes, int]] = []
    current: list[bytes] = []
    current_size = fixed
    for row in rows:
        encoded = canonical_json(row)[:-1]
        one_size = fixed + len(encoded)
        if one_size >= target_bytes:
            raise PublicationError("one record exceeds the artifact target byte limit")
        added = len(encoded) + (1 if current else 0)
        if current and current_size + added >= target_bytes:
            parts.append((prefix + b",".join(current) + suffix, len(current)))
            current = []
            current_size = fixed
            added = len(encoded)
        current.append(encoded)
        current_size += added

    # Empty datasets still get one valid, indexed shard.  This simplifies
    # consumers and makes zero-row coverage explicit.
    if current or not parts:
        parts.append((prefix + b",".join(current) + suffix, len(current)))
    return parts


def _pack_line_rows(
    header: bytes,
    rows: Iterable[bytes],
    target_bytes: int,
) -> list[tuple[bytes, int]]:
    if len(header) >= target_bytes:
        raise PublicationError("artifact header exceeds the target byte limit")
    parts: list[tuple[bytes, int]] = []
    current: list[bytes] = []
    size = len(header)
    for row in rows:
        if len(header) + len(row) >= target_bytes:
            raise PublicationError("one record exceeds the artifact target byte limit")
        if current and size + len(row) >= target_bytes:
            parts.append((header + b"".join(current), len(current)))
            current = []
            size = len(header)
        current.append(row)
        size += len(row)
    if current or not parts:
        parts.append((header + b"".join(current), len(current)))
    return parts


def _csv_line(values: Sequence[Any]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(
        [
            "'" + value
            if isinstance(value, str) and _CSV_FORMULA_PREFIX.match(value)
            else value
            for value in values
        ]
    )
    return stream.getvalue().encode("utf-8")


def _emit_json_shards(
    root: Path,
    prefix: str,
    base: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    target_bytes: int,
) -> list[dict]:
    descriptors = []
    for ordinal, (data, row_count) in enumerate(
        _pack_json_rows(base, rows, target_bytes)
    ):
        path = _content_path(prefix, ordinal, data, "json")
        _write(root, path, data)
        descriptors.append(
            _descriptor(path, data, row_count, "application/json")
        )
    return descriptors


def _emit_json_document(
    root: Path,
    prefix: str,
    document: Mapping[str, Any],
    target_bytes: int,
    *,
    rows: int | None = None,
) -> dict:
    data = canonical_json(document)
    if len(data) >= target_bytes:
        raise PublicationError(f"{prefix} exceeds the artifact target byte limit")
    path = _content_path(prefix, None, data, "json")
    _write(root, path, data)
    return _descriptor(path, data, rows, "application/json")


def _citation_index(
    root: Path,
    library_id: str,
    citation: Mapping[str, Any],
    target_bytes: int,
) -> dict:
    papers = citation.get("papers") or []
    if not isinstance(papers, list):
        raise PublicationError("citation papers must be a list")
    sorted_papers = sorted(
        (dict(paper) for paper in papers),
        key=lambda paper: (
            str(paper.get("publication_date") or ""),
            str(paper.get("doi") or ""),
            str(paper.get("title") or ""),
        ),
    )
    paper_parts = _emit_json_shards(
        root,
        f"citations/{library_id}",
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "citations",
            "library_id": library_id,
        },
        sorted_papers,
        target_bytes,
    )
    index = {
        key: value
        for key, value in citation.items()
        if key not in ("papers", "repo_papers")
    }
    index.update(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "citation_index",
            "library_id": library_id,
            "row_count": len(sorted_papers),
            "paper_parts": paper_parts,
            "repo_papers": citation.get("repo_papers") or {},
        }
    )
    return _emit_json_document(
        root,
        f"citations/{library_id}/index",
        index,
        target_bytes,
        rows=len(sorted_papers),
    )


_EXPORT_COLUMNS = (
    "full_name",
    "html_url",
    "owner",
    "description",
    "stars",
    "forks",
    "language",
    "archived",
    "created_at",
    "pushed_at",
    "earliest_integration",
    "visibility",
    "libraries_json",
)


def _exports(
    root: Path,
    repositories: Sequence[Mapping[str, Any]],
    target_bytes: int,
) -> dict:
    rows = [_export_repo_row(repo) for repo in repositories]
    rows.sort(key=lambda row: row["full_name"].casefold())

    json_lines = [canonical_json(row) for row in rows]
    json_parts = []
    for ordinal, (data, row_count) in enumerate(
        _pack_line_rows(b"", json_lines, target_bytes)
    ):
        path = _content_path(
            "exports/repositories/jsonl", ordinal, data, "jsonl"
        )
        _write(root, path, data)
        json_parts.append(
            _descriptor(path, data, row_count, "application/x-ndjson")
        )

    header = _csv_line(_EXPORT_COLUMNS)
    csv_lines = []
    for row in rows:
        csv_lines.append(
            _csv_line(
                [
                    json.dumps(row.get("libraries") or [], ensure_ascii=False, sort_keys=True)
                    if column == "libraries_json"
                    else row.get(column)
                    for column in _EXPORT_COLUMNS
                ]
            )
        )
    csv_parts = []
    for ordinal, (data, row_count) in enumerate(
        _pack_line_rows(header, csv_lines, target_bytes)
    ):
        path = _content_path("exports/repositories/csv", ordinal, data, "csv")
        _write(root, path, data)
        csv_parts.append(_descriptor(path, data, row_count, "text/csv"))

    index = {
        "schema_version": SCHEMA_VERSION,
        "kind": "repository_exports",
        "row_count": len(rows),
        "columns": list(_EXPORT_COLUMNS),
        "jsonl_parts": json_parts,
        "csv_parts": csv_parts,
    }
    return _emit_json_document(
        root,
        "exports/repositories/index",
        index,
        target_bytes,
        rows=len(rows),
    )


def _normalized_discovery_stats(
    raw_stats: object, library_ids: Iterable[str]
) -> dict[str, dict[str, Any]]:
    """Give legacy summaries and certificate-backed epochs honest labels."""
    supplied = raw_stats if isinstance(raw_stats, Mapping) else {}
    normalized: dict[str, dict[str, Any]] = {}
    for library_id in sorted(library_ids):
        raw = supplied.get(library_id)
        value = dict(raw) if isinstance(raw, Mapping) else {}
        certificates = value.get("certificates")
        if isinstance(certificates, list):
            value["evidence_kind"] = "certificates"
            value.setdefault("coverage_gaps", [])
            value.setdefault("sources", {})
            value.setdefault("source_lag_max_seconds", None)
            value.setdefault("stale", False)
            value.setdefault("carried_forward", False)
        elif value:
            value["evidence_kind"] = value.get(
                "evidence_kind", "legacy-summary"
            )
            value.setdefault("coverage_gaps", [])
            value.setdefault("sources", {})
            value.setdefault("source_lag_max_seconds", None)
            value.setdefault("stale", True)
            value.setdefault("carried_forward", True)
        else:
            value = {
                "evidence_kind": "not-evaluated",
                "coverage_gaps": [],
                "sources": {},
                "source_lag_max_seconds": None,
                "stale": True,
                "carried_forward": False,
            }
        normalized[library_id] = value
    return normalized


def _discovery_summary(
    raw_stats: object, library_id: str
) -> dict[str, Any]:
    """Small per-library coverage state suitable for the lazy index/card."""
    value = _normalized_discovery_stats(raw_stats, (library_id,))[library_id]
    sources = {}
    as_of_values = []
    for source, raw in sorted((value.get("sources") or {}).items()):
        if not isinstance(raw, Mapping):
            continue
        summary = {
            "complete": raw.get("complete"),
            "as_of": raw.get("as_of"),
            "stale": bool(raw.get("stale")),
            "carried_forward": bool(raw.get("carried_forward")),
        }
        sources[str(source)] = summary
        if isinstance(summary["as_of"], str) and summary["as_of"]:
            as_of_values.append(summary["as_of"])
    return {
        "evidence_kind": value.get("evidence_kind"),
        "as_of": max(as_of_values) if as_of_values else value.get("as_of"),
        "stale": bool(value.get("stale")),
        "carried_forward": bool(value.get("carried_forward")),
        "gap_count": len(value.get("coverage_gaps") or ()),
        "sources": sources,
    }


def build_v2_tree(
    current: Mapping[str, Any],
    timeseries: Mapping[str, Any] | None,
    citations: Mapping[str, Any] | None,
    deltas: Mapping[str, Any] | None,
    output_dir: str | os.PathLike[str],
    *,
    target_bytes: int = TARGET_ARTIFACT_BYTES,
) -> dict:
    """Build a complete V2 tree in an empty directory and return its manifest."""
    if target_bytes <= 0 or target_bytes > TARGET_ARTIFACT_BYTES:
        raise PublicationError(
            f"target_bytes is an exclusive limit between 1 and "
            f"{TARGET_ARTIFACT_BYTES}"
        )
    root = Path(output_dir)
    if root.exists() and any(root.iterdir()):
        raise PublicationError("V2 staging directory must be empty")
    root.mkdir(parents=True, exist_ok=True)

    libraries = current.get("libraries")
    repositories = current.get("repos")
    if not isinstance(libraries, list) or not isinstance(repositories, list):
        raise PublicationError("current document requires libraries and repos lists")
    visibility_attestation = _assert_publishable_source(repositories)
    if not isinstance(timeseries or {}, Mapping):
        raise PublicationError("timeseries must be an object")
    if not isinstance(citations or {}, Mapping):
        raise PublicationError("citations must be an object")
    citation_libraries = (citations or {}).get("libraries") or {}
    if not isinstance(citation_libraries, Mapping):
        raise PublicationError("citations.libraries must be an object")
    publication_day = _publication_date(
        current.get("generated_at"), "current.generated_at"
    )

    manifest_libraries = []
    library_ids: set[str] = set()
    for source_library in libraries:
        if not isinstance(source_library, Mapping):
            raise PublicationError("library cards must be objects")
        library = dict(source_library)
        library_id = _validate_library_id(library.get("id"))
        if library_id in library_ids:
            raise PublicationError("library IDs must be unique")
        library_ids.add(library_id)
        coverage = _classification_coverage(library)
        discovery_summary = _discovery_summary(
            current.get("discovery_stats"), library_id
        )

        repo_rows = []
        new_repos_7d = 0
        counts = {name: 0 for name in CLASSIFICATIONS}
        carried_counts = {name: 0 for name in CLASSIFICATIONS}
        for repo in repositories:
            entry = _effective_entry(repo, library)
            if entry is None:
                continue
            classification = entry.get("classification")
            if classification not in CLASSIFICATIONS:
                raise PublicationError("publishable rows require a supported classification")
            carried = _is_carried_forward_entry(entry)
            if (
                coverage[classification] == "not_evaluated"
                and not carried
            ):
                raise PublicationError(
                    "not_evaluated classifications cannot contain repository rows"
                )
            if carried:
                if coverage[classification] != "not_evaluated":
                    raise PublicationError(
                        "carried-forward evidence cannot satisfy current "
                        "classification coverage"
                    )
                carried_counts[classification] += 1
            else:
                counts[classification] += 1
                if _within_last_week(entry.get("first_integration"), publication_day):
                    new_repos_7d += 1
            repo_rows.append(_library_repo_row(repo, entry))
        # The detail page's initial viewport is newest-first. Stable two-pass
        # ordering keeps names ascending within equal dates while allowing it
        # to request only the first physical shard.
        repo_rows.sort(key=lambda row: row["full_name"].casefold())
        repo_rows.sort(
            key=lambda row: str(
                (row.get("libraries") or [{}])[0].get("first_integration") or ""
            ),
            reverse=True,
        )
        repo_parts = _emit_json_shards(
            root,
            f"libraries/{library_id}/repos",
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "repositories",
                "library_id": library_id,
            },
            repo_rows,
            target_bytes,
        )

        published_counts = {
            name: (counts[name] if coverage[name] == "evaluated" else None)
            for name in CLASSIFICATIONS
        }
        published_timeseries = dict((timeseries or {}).get(library_id) or {})
        index = {
            "schema_version": SCHEMA_VERSION,
            "kind": "library_index",
            "library_id": library_id,
            "row_count": len(repo_rows),
            "current_row_count": sum(counts.values()),
            "carried_forward_row_count": sum(carried_counts.values()),
            "carried_forward_classification_counts": carried_counts,
            "sort": "first_integration_desc,name_asc",
            "classification_counts": published_counts,
            "classification_coverage": coverage,
            "new_repos_7d": new_repos_7d,
            "discovery_coverage": discovery_summary,
            "timeseries": published_timeseries,
            "repo_parts": repo_parts,
        }
        index_descriptor = _emit_json_document(
            root,
            f"libraries/{library_id}/index",
            index,
            target_bytes,
            rows=len(repo_rows),
        )

        citation = citation_libraries.get(library_id)
        citation_descriptor = None
        if citation is not None:
            if not isinstance(citation, Mapping):
                raise PublicationError("citation library values must be objects")
            citation_descriptor = _citation_index(
                root, library_id, citation, target_bytes
            )

        card = dict(library)
        timeseries_as_of = published_timeseries.get("as_of")
        if not timeseries_as_of:
            migration = current.get("migration_quality") or {}
            if library_id in set(migration.get("carried_forward_library_ids", ())):
                timeseries_as_of = migration.get("legacy_as_of")
        if timeseries_as_of:
            card["timeseries_as_of"] = timeseries_as_of
        card["classification_coverage"] = coverage
        card["discovery_coverage"] = discovery_summary
        card["new_repos_7d"] = new_repos_7d
        for classification in CLASSIFICATIONS:
            if coverage[classification] == "not_evaluated":
                card[f"{classification}_count"] = None
        if (
            coverage["confirmed"] == "not_evaluated"
            or (
                card.get("adoption_counts_build")
                and coverage["bundled"] == "not_evaluated"
            )
        ):
            card["headline_count"] = None
        card["index"] = index_descriptor
        if citation_descriptor:
            card["citations_index"] = citation_descriptor
            card["citation_total"] = citation.get("total", 0)
            card["citation_new_since_last"] = citation.get("new_since_last", 0)
            card["citation_new_7d"] = citation.get("new_7d")
        else:
            card["citations_index"] = None
            card["citation_total"] = None
            card["citation_new_since_last"] = None
            card["citation_new_7d"] = None
        manifest_libraries.append(card)

    manifest_libraries.sort(
        key=lambda library: (
            int(library.get("display_order", 1_000_000)),
            str(library.get("id")),
        )
    )

    quality = {
        "schema_version": SCHEMA_VERSION,
        "kind": "quality",
        "caveats": current.get("caveats") or [],
        "discovery_stats": _normalized_discovery_stats(
            current.get("discovery_stats"), library_ids
        ),
        "scan": dict(current.get("scan_quality") or {
            "evidence_kind": "legacy-summary",
            "mode": "legacy",
            "coverage_claim": "legacy-summary",
            "selected_repositories": None,
            "files_examined": None,
            "bytes_examined": None,
            "skipped_large_files": None,
            "pruned_large_assets": None,
            "policy": None,
            "freshness": None,
            "complete": None,
        }),
        "migration": dict(current.get("migration_quality") or {
            "mixed_v1_v2": False,
            "stale": False,
            "carried_forward_library_ids": [],
            "selected_library_ids": [],
            "legacy_as_of": None,
        }),
        "deduped_mirror_count": len(current.get("deduped_mirrors") or []),
        "citation": {
            "source": (citations or {}).get("source"),
            "method_version": (citations or {}).get("method_version"),
            "caveats": (citations or {}).get("caveats") or [],
        },
    }
    quality_descriptor = _emit_json_document(root, "quality", quality, target_bytes)
    delta_document = dict(deltas or {})
    delta_document["schema_version"] = SCHEMA_VERSION
    delta_document["kind"] = "deltas"
    deltas_descriptor = _emit_json_document(
        root, "deltas", delta_document, target_bytes
    )
    exports_descriptor = _exports(root, repositories, target_bytes)

    release_metadata = current.get("release_metadata") or {}
    if not isinstance(release_metadata, Mapping):
        raise PublicationError("release_metadata must be an object")
    portfolio_coverage = current.get("portfolio_coverage")
    if portfolio_coverage is not None and not isinstance(
        portfolio_coverage, Mapping
    ):
        raise PublicationError("portfolio_coverage must be an object")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "release": {
            "generated_at": current.get("generated_at"),
            "method_version": current.get("method_version"),
            "detection_hash": current.get("detection_hash"),
            "prev_refresh": current.get("prev_refresh"),
            "is_bootstrap": bool(current.get("is_bootstrap")),
            "source_visibility_attestation": visibility_attestation,
            **dict(release_metadata),
        },
        "generated_at": current.get("generated_at"),
        "totals": current.get("totals") or {},
        "caveats": current.get("caveats") or [],
        "libraries": manifest_libraries,
        "quality": quality_descriptor,
        "deltas": deltas_descriptor,
        "exports": exports_descriptor,
    }
    if portfolio_coverage is not None:
        manifest["portfolio_coverage"] = dict(portfolio_coverage)
    manifest["release"]["id"] = _release_identity(manifest)
    manifest_data = canonical_json(manifest)
    if len(manifest_data) > MAX_MANIFEST_BYTES:
        raise PublicationError(
            f"manifest is {len(manifest_data)} bytes; limit is {MAX_MANIFEST_BYTES}"
        )
    if len(manifest_data) >= HARD_ARTIFACT_BYTES:
        raise PublicationError("manifest exceeds the universal hard byte limit")
    _write(root, "manifest.json", manifest_data)
    return manifest


def _tree_files(root: Path) -> set[str]:
    if not root.exists():
        return set()
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }


def _assert_real_tree(root: Path, label: str) -> None:
    """Refuse publication trees whose writes could escape through symlinks."""
    if root.is_symlink():
        raise PublicationError(f"{label} root must not be a symlink")
    if root.exists() and not root.is_dir():
        raise PublicationError(f"{label} root must be a directory")
    if root.exists():
        for path in root.rglob("*"):
            if path.is_symlink():
                raise PublicationError(
                    f"{label} tree must not contain symlinks"
                )


def _restore_manifest(live: Path, prior_manifest: bytes | None) -> None:
    if prior_manifest is None:
        (live / "manifest.json").unlink(missing_ok=True)
        return
    rollback = live / ".manifest.json.rollback"
    rollback.write_bytes(prior_manifest)
    os.replace(rollback, live / "manifest.json")


@dataclass
class InstalledV2Transaction:
    """A validated live swap that can still restore the previous release."""

    live: Path
    prior_files: set[str]
    prior_manifest: bytes | None
    quarantine: Path
    committed: bool = False

    def rollback(self) -> None:
        if self.committed:
            return
        for source in sorted(
            (path for path in self.quarantine.rglob("*") if path.is_file()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            relative = source.relative_to(self.quarantine)
            destination = self.live / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
        _restore_manifest(self.live, self.prior_manifest)
        for relative in sorted(_tree_files(self.live) - self.prior_files):
            path = self.live / relative
            if path.is_file() or path.is_symlink():
                path.unlink(missing_ok=True)
        for path in self.live.rglob("*.publishing"):
            path.unlink(missing_ok=True)
        for directory in sorted(
            (path for path in self.live.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            try:
                directory.rmdir()
            except OSError:
                pass
        shutil.rmtree(self.quarantine, ignore_errors=True)

    def commit(self) -> None:
        if self.committed:
            return
        shutil.rmtree(self.quarantine, ignore_errors=True)
        self.committed = True


def _install_staged_tree(
    staging: Path,
    live: Path,
    *,
    target_bytes: int = TARGET_ARTIFACT_BYTES,
    provisional: bool = False,
) -> InstalledV2Transaction | None:
    """Install manifest-last, validate, then quarantine every unreferenced file."""
    from .validate_v2 import validate_v2

    _assert_real_tree(staging, "staged V2")
    _assert_real_tree(live, "live V2")
    live.mkdir(parents=True, exist_ok=True)
    _assert_real_tree(live, "live V2")
    expected_files = _tree_files(staging)
    if "manifest.json" not in expected_files:
        raise PublicationError("staged V2 tree has no manifest")
    prior_files = _tree_files(live)
    prior_manifest = (
        (live / "manifest.json").read_bytes()
        if (live / "manifest.json").is_file()
        else None
    )
    artifacts = sorted(
        path
        for path in staging.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    )
    quarantine = Path(
        tempfile.mkdtemp(prefix=f".{live.name}-superseded-", dir=live.parent)
    )
    moved: list[str] = []
    transaction = InstalledV2Transaction(
        live=live,
        prior_files=prior_files,
        prior_manifest=prior_manifest,
        quarantine=quarantine,
    )
    try:
        for source in artifacts:
            relative = source.relative_to(staging)
            destination = live / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                if destination.read_bytes() == source.read_bytes():
                    continue
                raise PublicationError(
                    "content-addressed artifact path contains different bytes"
                )
            temporary = destination.with_name(destination.name + ".publishing")
            shutil.copyfile(source, temporary)
            os.replace(temporary, destination)

        manifest_source = staging / "manifest.json"
        manifest_temporary = live / ".manifest.json.publishing"
        shutil.copyfile(manifest_source, manifest_temporary)
        os.replace(manifest_temporary, live / "manifest.json")

        errors = validate_v2(
            live,
            target_bytes=target_bytes,
            require_artifact_closure=False,
        )
        if errors:
            raise PublicationError(
                "V2 live validation failed:\n- " + "\n- ".join(errors)
            )

        for relative in sorted(_tree_files(live) - expected_files):
            source = live / relative
            destination = quarantine / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
            moved.append(relative)
        for directory in sorted(
            (path for path in live.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            try:
                directory.rmdir()
            except OSError:
                pass

        closure_errors = validate_v2(
            live,
            target_bytes=target_bytes,
            require_artifact_closure=True,
        )
        if closure_errors:
            raise PublicationError(
                "V2 artifact closure validation failed:\n- "
                + "\n- ".join(closure_errors)
            )
    except BaseException:
        transaction.rollback()
        raise
    if provisional:
        return transaction
    transaction.commit()
    return None


@dataclass
class StagedV2Publication:
    """A fully validated V2 tree whose live pointer has not changed."""

    root: Path
    manifest: dict
    target_bytes: int
    _temporary: tempfile.TemporaryDirectory

    def install(self, output_dir: str | os.PathLike[str]) -> dict:
        _install_staged_tree(
            self.root, Path(output_dir), target_bytes=self.target_bytes
        )
        return self.manifest

    def provisional_install(
        self, output_dir: str | os.PathLike[str]
    ) -> InstalledV2Transaction:
        transaction = _install_staged_tree(
            self.root,
            Path(output_dir),
            target_bytes=self.target_bytes,
            provisional=True,
        )
        if transaction is None:  # pragma: no cover - defensive type narrowing
            raise PublicationError("provisional install did not retain rollback")
        return transaction

    def close(self) -> None:
        self._temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        self.close()


def stage_v2(
    current: Mapping[str, Any],
    timeseries: Mapping[str, Any] | None,
    citations: Mapping[str, Any] | None,
    deltas: Mapping[str, Any] | None,
    output_dir: str | os.PathLike[str],
    *,
    target_bytes: int = TARGET_ARTIFACT_BYTES,
) -> StagedV2Publication:
    """Build and validate V2 without changing the live output directory."""
    live = Path(output_dir)
    live.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(
        prefix=f".{live.name}-staging-", dir=live.parent
    )
    staging = Path(temporary.name)
    try:
        manifest = build_v2_tree(
            current,
            timeseries,
            citations,
            deltas,
            staging,
            target_bytes=target_bytes,
        )
        from .validate_v2 import compare_v1_v2, validate_v2

        errors = validate_v2(
            staging,
            target_bytes=target_bytes,
            require_artifact_closure=True,
        )
        if errors:
            raise PublicationError(
                "V2 staging validation failed:\n- " + "\n- ".join(errors)
            )
        parity_errors = compare_v1_v2(
            current,
            timeseries,
            citations,
            staging,
            deltas,
        )
        if parity_errors:
            raise PublicationError(
                "V1/V2 staging reconciliation failed:\n- "
                + "\n- ".join(parity_errors)
            )
        return StagedV2Publication(
            staging, manifest, target_bytes, temporary
        )
    except BaseException:
        temporary.cleanup()
        raise


def publish_v2(
    current: Mapping[str, Any],
    timeseries: Mapping[str, Any] | None,
    citations: Mapping[str, Any] | None,
    deltas: Mapping[str, Any] | None,
    output_dir: str | os.PathLike[str],
    *,
    target_bytes: int = TARGET_ARTIFACT_BYTES,
) -> dict:
    """Build, fully validate, and atomically publish V2 artifacts."""
    with stage_v2(
        current,
        timeseries,
        citations,
        deltas,
        output_dir,
        target_bytes=target_bytes,
    ) as staged:
        return staged.install(output_dir)


def _load_json(path: Path, *, optional: bool = False) -> dict:
    if optional and not path.exists():
        return {}
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise PublicationError(f"{path.name} must contain an object")
    return value


def publish_from_v1(
    data_dir: str | os.PathLike[str],
    output_dir: str | os.PathLike[str] | None = None,
    *,
    target_bytes: int = TARGET_ARTIFACT_BYTES,
) -> dict:
    """Dual-write V2 from an existing V1 data directory."""
    data = Path(data_dir)
    output = Path(output_dir) if output_dir is not None else data / "v2"
    current = _load_json(data / "current.json")
    raw_timeseries = _load_json(data / "timeseries.json")
    carried = set(
        (current.get("migration_quality") or {}).get(
            "carried_forward_library_ids", ()
        )
    )
    timeseries = {}
    for library_id, raw_series in raw_timeseries.items():
        if not isinstance(raw_series, Mapping):
            timeseries[library_id] = raw_series
            continue
        series = dict(raw_series)
        fallback_as_of = (
            None
            if library_id in carried
            else str(current.get("generated_at") or "")[:10]
        )
        if fallback_as_of:
            series.setdefault("as_of", fallback_as_of)
        timeseries[library_id] = series
    return publish_v2(
        current,
        timeseries,
        _load_json(data / "citations.json", optional=True),
        _load_json(data / "deltas.json", optional=True),
        output,
        target_bytes=target_bytes,
    )


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    print(
        "ERROR: collector.publish_v2 is a retired migration helper; use "
        "`python3.12 -m collector.cli refresh` (or `validate`/`reconcile`)",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
