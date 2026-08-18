"""Universal validator and V1/V2 parity gate for manifest-driven publication."""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .publish_v2 import (
    CLASSIFICATIONS,
    HARD_ARTIFACT_BYTES,
    LEGACY_VISIBILITY_ATTESTATION,
    MAX_MANIFEST_BYTES,
    SCHEMA_VERSION,
    STATE_VISIBILITY_ATTESTATION,
    TARGET_ARTIFACT_BYTES,
    _PRIVATE_MARKER_FIELDS,
    _CSV_FORMULA_PREFIX,
    _UNUSED_REPOSITORY_FIELDS,
    _effective_entry,
    _has_non_public_marker,
    _release_identity,
    _within_last_week,
    canonical_json,
)
from .scanner_v2 import SCAN_FRESHNESS, SCAN_POLICY


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _safe_relative(path: object) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or "\\" in path:
        return None
    return path


class _Validation:
    def __init__(self, root: Path, target_bytes: int):
        self.root = root
        self.target_bytes = target_bytes
        self.errors: list[str] = []
        self.paths: set[str] = set()

    def error(self, message: str) -> None:
        self.errors.append(message)

    def artifact(
        self, descriptor: object, label: str, expected_media: str | None = None
    ) -> tuple[Path | None, bytes | None]:
        if not isinstance(descriptor, Mapping):
            self.error(f"{label} descriptor is missing or not an object")
            return None, None
        relative = _safe_relative(descriptor.get("path"))
        if relative is None:
            self.error(f"{label} has an unsafe or missing path")
            return None, None
        if relative in self.paths:
            self.error(f"artifact path is indexed more than once: {relative}")
            return None, None
        self.paths.add(relative)
        path = self.root / relative
        if path.is_symlink():
            self.error(f"{label} must not be a symlink")
            return path, None
        if not path.is_file():
            self.error(f"{label} is missing: {relative}")
            return path, None
        try:
            data = path.read_bytes()
        except OSError as exc:
            self.error(f"{label} cannot be read: {exc}")
            return path, None
        actual_size = len(data)
        if descriptor.get("bytes") != actual_size:
            self.error(f"{label} byte count does not match its descriptor")
        if actual_size >= self.target_bytes:
            self.error(
                f"{label} is {actual_size} bytes; target limit is strictly below "
                f"{self.target_bytes}"
            )
        if actual_size >= HARD_ARTIFACT_BYTES:
            self.error(
                f"{label} is {actual_size} bytes; hard limit is strictly below "
                f"{HARD_ARTIFACT_BYTES}"
            )
        digest = hashlib.sha256(data).hexdigest()
        if descriptor.get("sha256") != digest:
            self.error(f"{label} SHA-256 does not match")
        media = descriptor.get("media_type")
        if not isinstance(media, str) or not media:
            self.error(f"{label} media_type is missing")
        elif expected_media and media != expected_media:
            self.error(f"{label} media_type is {media}, expected {expected_media}")
        rows = descriptor.get("rows")
        if rows is not None and (not isinstance(rows, int) or isinstance(rows, bool) or rows < 0):
            self.error(f"{label} rows must be a non-negative integer")
        return path, data

    def json_artifact(
        self, descriptor: object, label: str
    ) -> tuple[Path | None, Any]:
        path, data = self.artifact(descriptor, label, "application/json")
        if data is None:
            return path, None
        try:
            document = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.error(f"{label} is invalid JSON: {exc}")
            return path, None
        if not isinstance(document, dict):
            self.error(f"{label} JSON root must be an object")
            return path, None
        if document.get("schema_version") != SCHEMA_VERSION:
            self.error(f"{label} has an unsupported schema_version")
        return path, document


def _manifest(root: Path, validator: _Validation) -> dict | None:
    path = root / "manifest.json"
    if path.is_symlink():
        validator.error("manifest.json must not be a symlink")
        return None
    if not path.is_file():
        validator.error("manifest.json is missing")
        return None
    try:
        data = path.read_bytes()
    except OSError as exc:
        validator.error(f"manifest.json cannot be read: {exc}")
        return None
    if len(data) > MAX_MANIFEST_BYTES:
        validator.error(
            f"manifest.json is {len(data)} bytes; maximum is {MAX_MANIFEST_BYTES}"
        )
    if len(data) >= HARD_ARTIFACT_BYTES:
        validator.error("manifest.json exceeds the universal hard size limit")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        validator.error(f"manifest.json is invalid JSON: {exc}")
        return None
    if not isinstance(value, dict):
        validator.error("manifest.json root must be an object")
        return None
    if value.get("schema_version") != SCHEMA_VERSION:
        validator.error("manifest.json has an unsupported schema_version")
    return value


def _validate_repo_rows(
    validator: _Validation,
    library_id: str,
    index: Mapping[str, Any],
    publication_day: datetime.date,
) -> tuple[dict[str, int], set[str], set[str], int]:
    measured = {name: 0 for name in CLASSIFICATIONS}
    carried_measured = {name: 0 for name in CLASSIFICATIONS}
    all_names: set[str] = set()
    confirmed_names: set[str] = set()
    new_repos_7d = 0
    descriptors = index.get("repo_parts")
    if not isinstance(descriptors, list) or not descriptors:
        validator.error(f"{library_id} repo_parts must be a non-empty list")
        return measured, all_names, confirmed_names, new_repos_7d
    rows_seen = 0
    prior_sort: tuple[str, str] | None = None
    for ordinal, descriptor in enumerate(descriptors):
        label = f"{library_id} repository part {ordinal}"
        _path, shard = validator.json_artifact(descriptor, label)
        if not isinstance(shard, Mapping):
            continue
        if shard.get("kind") != "repositories" or shard.get("library_id") != library_id:
            validator.error(f"{label} has the wrong kind or library_id")
        rows = shard.get("rows")
        if not isinstance(rows, list):
            validator.error(f"{label} rows must be a list")
            continue
        if isinstance(descriptor, Mapping) and descriptor.get("rows") != len(rows):
            validator.error(f"{label} row count does not match its descriptor")
        rows_seen += len(rows)
        for row in rows:
            if not isinstance(row, Mapping):
                validator.error(f"{label} contains a non-object row")
                continue
            # Do not include a possibly private repository name in diagnostics.
            if row.get("visibility") != "PUBLIC":
                validator.error(f"{label} contains a row not explicitly marked PUBLIC")
            if _has_non_public_marker(row):
                validator.error(f"{label} contains a private repository row")
            if _PRIVATE_MARKER_FIELDS.intersection(row) or "is_public" in row:
                validator.error(
                    f"{label} contains internal visibility marker fields"
                )
            if _UNUSED_REPOSITORY_FIELDS.intersection(row):
                validator.error(
                    f"{label} contains unused legacy repository fields"
                )
            name = row.get("full_name")
            if not isinstance(name, str) or not name:
                validator.error(f"{label} contains a row without full_name")
                continue
            folded = name.casefold()
            if folded in all_names:
                validator.error(f"{library_id} contains a duplicate repository row")
                continue
            all_names.add(folded)
            entries = row.get("libraries")
            if not isinstance(entries, list) or len(entries) != 1:
                validator.error(f"{label} rows require exactly one library entry")
                continue
            entry = entries[0]
            if not isinstance(entry, Mapping) or entry.get("library_id") != library_id:
                validator.error(f"{label} contains an entry for the wrong library")
                continue
            classification = entry.get("classification")
            if classification not in CLASSIFICATIONS:
                validator.error(f"{label} contains an unsupported classification")
                continue
            carried = entry.get("carried_forward") is True
            if carried and (
                entry.get("stale") is not True
                or not isinstance(entry.get("as_of"), str)
                or not entry.get("as_of")
            ):
                validator.error(
                    f"{label} carried-forward row lacks stale as-of provenance"
                )
            current_sort = (
                str(entry.get("first_integration") or ""),
                folded,
            )
            if prior_sort is not None:
                if current_sort[0] > prior_sort[0] or (
                    current_sort[0] == prior_sort[0]
                    and current_sort[1] < prior_sort[1]
                ):
                    validator.error(
                        f"{library_id} repository rows are not deterministic-sorted"
                    )
            prior_sort = current_sort
            if carried:
                carried_measured[classification] += 1
            else:
                measured[classification] += 1
                if _within_last_week(
                    entry.get("first_integration"), publication_day
                ):
                    new_repos_7d += 1
            if classification == "confirmed" and not carried:
                confirmed_names.add(folded)
    if index.get("row_count") != rows_seen:
        validator.error(f"{library_id} index row_count does not match its shards")
    coverage = index.get("classification_coverage")
    if not isinstance(coverage, Mapping):
        validator.error(f"{library_id} classification_coverage is missing")
    else:
        for classification in CLASSIFICATIONS:
            state = coverage.get(classification)
            if state not in ("evaluated", "not_evaluated"):
                validator.error(
                    f"{library_id} has invalid {classification} coverage state"
                )
            if state == "not_evaluated" and measured[classification]:
                validator.error(
                    f"{library_id} has rows for not_evaluated {classification}"
                )
            if state == "evaluated" and carried_measured[classification]:
                validator.error(
                    f"{library_id} current coverage contains carried-forward "
                    f"{classification} rows"
                )
        expected_counts = {
            classification: (
                measured[classification]
                if coverage.get(classification) == "evaluated"
                else None
            )
            for classification in CLASSIFICATIONS
        }
        if index.get("classification_counts") != expected_counts:
            validator.error(
                f"{library_id} classification_counts do not reconcile to "
                "coverage and repository rows"
            )
    cohort_count_fields = (
        "current_row_count",
        "carried_forward_row_count",
        "carried_forward_classification_counts",
    )
    if any(field in index for field in cohort_count_fields):
        if index.get("current_row_count") != sum(measured.values()):
            validator.error(
                f"{library_id} current_row_count does not match repository rows"
            )
        if index.get("carried_forward_row_count") != sum(
            carried_measured.values()
        ):
            validator.error(
                f"{library_id} carried_forward_row_count does not match rows"
            )
        if (
            index.get("carried_forward_classification_counts")
            != carried_measured
        ):
            validator.error(
                f"{library_id} carried-forward classifications do not reconcile"
            )
    elif any(carried_measured.values()):
        validator.error(
            f"{library_id} carried-forward rows lack explicit index counts"
        )
    return measured, all_names, confirmed_names, new_repos_7d


def _validate_citations(
    validator: _Validation,
    library_id: str,
    descriptor: object,
) -> Mapping[str, Any] | None:
    _path, index = validator.json_artifact(
        descriptor, f"{library_id} citation index"
    )
    if not isinstance(index, Mapping):
        return None
    if index.get("kind") != "citation_index" or index.get("library_id") != library_id:
        validator.error(f"{library_id} citation index has wrong kind or library_id")
    if isinstance(descriptor, Mapping) and descriptor.get("rows") != index.get(
        "row_count"
    ):
        validator.error(f"{library_id} citation index descriptor row count differs")
    parts = index.get("paper_parts")
    if not isinstance(parts, list) or not parts:
        validator.error(f"{library_id} citation paper_parts must be non-empty")
        return None
    rows_seen = 0
    identities: set[tuple[str, str]] = set()
    for ordinal, part in enumerate(parts):
        label = f"{library_id} citation part {ordinal}"
        _part_path, shard = validator.json_artifact(part, label)
        if not isinstance(shard, Mapping):
            continue
        if shard.get("kind") != "citations" or shard.get("library_id") != library_id:
            validator.error(f"{label} has wrong kind or library_id")
        rows = shard.get("rows")
        if not isinstance(rows, list):
            validator.error(f"{label} rows must be a list")
            continue
        if isinstance(part, Mapping) and part.get("rows") != len(rows):
            validator.error(f"{label} row count does not match its descriptor")
        rows_seen += len(rows)
        for paper in rows:
            if not isinstance(paper, Mapping):
                validator.error(f"{label} contains a non-object paper")
                continue
            identity = (
                str(paper.get("doi") or "").casefold(),
                str(paper.get("title") or "").casefold(),
            )
            if identity in identities:
                validator.error(f"{library_id} contains a duplicate citation row")
            identities.add(identity)
    if index.get("row_count") != rows_seen:
        validator.error(f"{library_id} citation row_count does not match its shards")
    total = index.get("total")
    # OpenAlex total may exceed a deliberately capped paper list.  In the
    # ordinary uncapped case it must exactly equal the published rows.
    if not index.get("papers_capped") and isinstance(total, int) and total != rows_seen:
        validator.error(f"{library_id} citation total does not reconcile to paper rows")
    return index


def _validate_exports(
    validator: _Validation, descriptor: object
) -> set[str]:
    _path, index = validator.json_artifact(descriptor, "repository export index")
    if not isinstance(index, Mapping):
        return set()
    if index.get("kind") != "repository_exports":
        validator.error("repository export index has wrong kind")
    expected = index.get("row_count")
    if isinstance(descriptor, Mapping) and descriptor.get("rows") != expected:
        validator.error("repository export index descriptor row count differs")
    json_names: set[str] = set()
    json_rows = 0
    parts = index.get("jsonl_parts")
    if not isinstance(parts, list) or not parts:
        validator.error("repository export JSONL parts must be non-empty")
    else:
        for ordinal, part in enumerate(parts):
            _part_path, data = validator.artifact(
                part, f"repository JSONL export part {ordinal}", "application/x-ndjson"
            )
            if data is None:
                continue
            rows = [line for line in data.splitlines() if line]
            if isinstance(part, Mapping) and part.get("rows") != len(rows):
                validator.error(
                    f"repository JSONL export part {ordinal} row count mismatch"
                )
            json_rows += len(rows)
            for line in rows:
                try:
                    row = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    validator.error(
                        f"repository JSONL export part {ordinal} contains invalid JSON"
                    )
                    continue
                if not isinstance(row, Mapping) or row.get("visibility") != "PUBLIC":
                    validator.error(
                        f"repository JSONL export part {ordinal} contains a non-public row"
                    )
                    continue
                if _has_non_public_marker(row):
                    validator.error(
                        f"repository JSONL export part {ordinal} contains "
                        "a private repository row"
                    )
                if (
                    _PRIVATE_MARKER_FIELDS.intersection(row)
                    or "is_public" in row
                ):
                    validator.error(
                        f"repository JSONL export part {ordinal} contains "
                        "internal visibility marker fields"
                    )
                if _UNUSED_REPOSITORY_FIELDS.intersection(row):
                    validator.error(
                        f"repository JSONL export part {ordinal} contains "
                        "unused legacy repository fields"
                    )
                name = row.get("full_name")
                if not isinstance(name, str) or not name:
                    validator.error(
                        f"repository JSONL export part {ordinal} has missing full_name"
                    )
                    continue
                folded = name.casefold()
                if folded in json_names:
                    validator.error("repository JSONL export contains duplicate rows")
                json_names.add(folded)
    if expected != json_rows:
        validator.error("repository JSONL export does not reconcile to index row_count")

    csv_rows = 0
    csv_names: set[str] = set()
    csv_parts = index.get("csv_parts")
    if not isinstance(csv_parts, list) or not csv_parts:
        validator.error("repository export CSV parts must be non-empty")
    else:
        for ordinal, part in enumerate(csv_parts):
            _part_path, data = validator.artifact(
                part, f"repository CSV export part {ordinal}", "text/csv"
            )
            if data is None:
                continue
            try:
                reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
                rows = list(reader)
            except (UnicodeDecodeError, csv.Error):
                validator.error(f"repository CSV export part {ordinal} is invalid")
                continue
            if reader.fieldnames != index.get("columns"):
                validator.error(f"repository CSV export part {ordinal} header mismatch")
            if isinstance(part, Mapping) and part.get("rows") != len(rows):
                validator.error(
                    f"repository CSV export part {ordinal} row count mismatch"
                )
            csv_rows += len(rows)
            for row in rows:
                if any(
                    isinstance(value, str)
                    and _CSV_FORMULA_PREFIX.match(value)
                    for value in row.values()
                ):
                    validator.error(
                        f"repository CSV export part {ordinal} contains "
                        "a formula-leading cell"
                    )
                if row.get("visibility") != "PUBLIC":
                    validator.error(
                        f"repository CSV export part {ordinal} contains a non-public row"
                    )
                folded = (row.get("full_name") or "").casefold()
                if not folded or folded in csv_names:
                    validator.error("repository CSV export contains missing/duplicate rows")
                csv_names.add(folded)
    if expected != csv_rows:
        validator.error("repository CSV export does not reconcile to index row_count")
    if csv_names != json_names:
        validator.error("repository CSV and JSONL export membership differs")
    return json_names


def _validate_discovery_quality(
    validator: _Validation,
    quality: Mapping[str, Any],
    library_ids: set[str],
) -> None:
    stats = quality.get("discovery_stats")
    if not isinstance(stats, Mapping):
        validator.error("quality discovery_stats must be an object")
        return
    if set(stats) != library_ids:
        validator.error(
            "quality discovery_stats membership differs from manifest libraries"
        )
    for library_id in sorted(library_ids):
        item = stats.get(library_id)
        if not isinstance(item, Mapping):
            validator.error(f"{library_id} discovery quality must be an object")
            continue
        kind = item.get("evidence_kind")
        if kind not in (
            "certificates",
            "legacy-summary",
            "carried-forward-v1",
            "not-evaluated",
        ):
            validator.error(f"{library_id} discovery evidence_kind is invalid")
            continue
        gaps = item.get("coverage_gaps")
        sources = item.get("sources")
        lag = item.get("source_lag_max_seconds")
        if not isinstance(gaps, list):
            validator.error(f"{library_id} discovery coverage_gaps must be a list")
        if not isinstance(sources, Mapping):
            validator.error(f"{library_id} discovery sources must be an object")
        if lag is not None and (
            not isinstance(lag, int) or isinstance(lag, bool) or lag < 0
        ):
            validator.error(
                f"{library_id} discovery source_lag_max_seconds is invalid"
            )
        if kind != "certificates":
            if kind in ("legacy-summary", "carried-forward-v1") and (
                item.get("stale") is not True
                or item.get("carried_forward") is not True
            ):
                validator.error(
                    f"{library_id} carried discovery quality must be stale"
                )
            continue

        certificates = item.get("certificates")
        if not isinstance(certificates, list) or not certificates:
            validator.error(
                f"{library_id} certificate-backed discovery quality is empty"
            )
            continue
        expected_gaps: list[dict[str, Any]] = []
        expected_sources: dict[str, list[Mapping[str, Any]]] = {}
        lag_values: list[int] = []
        identities: set[tuple[str, str]] = set()
        for certificate in certificates:
            if not isinstance(certificate, Mapping):
                validator.error(
                    f"{library_id} discovery certificate must be an object"
                )
                continue
            source = certificate.get("source")
            query_fp = certificate.get("query_fingerprint")
            identity = (str(source or ""), str(query_fp or ""))
            if not all(identity) or identity in identities:
                validator.error(
                    f"{library_id} discovery certificate identity is invalid/duplicate"
                )
            identities.add(identity)
            if certificate.get("library_id") != library_id:
                validator.error(
                    f"{library_id} discovery certificate library_id differs"
                )
            if certificate.get("complete") is not True:
                validator.error(
                    f"{library_id} published discovery certificate is incomplete"
                )
            if (
                certificate.get("terminal") is not True
                or not isinstance(certificate.get("epoch_completed_at"), str)
            ):
                validator.error(
                    f"{library_id} discovery certificate is not terminal"
                )
            certificate_gaps = certificate.get("gaps")
            if not isinstance(certificate_gaps, list):
                validator.error(
                    f"{library_id} discovery certificate gaps must be a list"
                )
                certificate_gaps = []
            for gap in certificate_gaps:
                if isinstance(gap, Mapping):
                    expected_gaps.append(
                        {
                            "source": source,
                            "query_fingerprint": query_fp,
                            **dict(gap),
                        }
                    )
                else:
                    validator.error(
                        f"{library_id} discovery certificate gap must be an object"
                    )
            certificate_lag = certificate.get("source_lag_max_seconds")
            if certificate_lag is not None:
                if (
                    not isinstance(certificate_lag, int)
                    or isinstance(certificate_lag, bool)
                    or certificate_lag < 0
                ):
                    validator.error(
                        f"{library_id} discovery certificate lag is invalid"
                    )
                else:
                    lag_values.append(certificate_lag)
            if isinstance(source, str) and source:
                expected_sources.setdefault(source, []).append(certificate)

        expected_gaps.sort(
            key=lambda value: canonical_json(value)
        )
        actual_gaps = list(gaps) if isinstance(gaps, list) else []
        actual_gaps.sort(key=lambda value: canonical_json(value))
        if actual_gaps != expected_gaps:
            validator.error(
                f"{library_id} discovery gaps do not reconcile to certificates"
            )
        expected_lag = max(lag_values) if lag_values else None
        if lag != expected_lag:
            validator.error(
                f"{library_id} discovery lag does not reconcile to certificates"
            )
        if isinstance(sources, Mapping):
            if set(sources) != set(expected_sources):
                validator.error(
                    f"{library_id} discovery source membership differs"
                )
            for source, source_certificates in expected_sources.items():
                summary = sources.get(source)
                if not isinstance(summary, Mapping):
                    continue
                source_lags = [
                    value["source_lag_max_seconds"]
                    for value in source_certificates
                    if isinstance(value.get("source_lag_max_seconds"), int)
                ]
                expected = {
                    "certificate_count": len(source_certificates),
                    "complete": all(
                        value.get("complete") is True
                        for value in source_certificates
                    ),
                    "terminal": all(
                        value.get("terminal") is True
                        for value in source_certificates
                    ),
                    "observations_count": sum(
                        int(value.get("observations_count") or 0)
                        for value in source_certificates
                    ),
                    "quarantined_count": sum(
                        int(value.get("quarantined_count") or 0)
                        for value in source_certificates
                    ),
                    "source_lag_max_seconds": (
                        max(source_lags) if source_lags else None
                    ),
                    "epoch_started_at": min(
                        str(value.get("epoch_started_at") or "")
                        for value in source_certificates
                    ),
                    "epoch_completed_at": max(
                        str(value.get("epoch_completed_at") or "")
                        for value in source_certificates
                    ),
                    "carried_forward": any(
                        value.get("carried_forward") is True
                        for value in source_certificates
                    ),
                    "as_of": max(
                        str(
                            value.get("as_of")
                            or value.get("epoch_completed_at")
                            or ""
                        )
                        for value in source_certificates
                    ),
                    "stale": any(
                        value.get("stale") is True
                        for value in source_certificates
                    ),
                }
                if dict(summary) != expected:
                    validator.error(
                        f"{library_id} {source} discovery summary differs "
                        "from certificates"
                    )


def _validate_scan_and_migration_quality(
    validator: _Validation,
    quality: Mapping[str, Any],
    library_ids: set[str],
) -> None:
    scan = quality.get("scan")
    if not isinstance(scan, Mapping):
        validator.error("quality scan must be an object")
    elif scan.get("evidence_kind") != "legacy-summary":
        mode = scan.get("mode")
        claim = scan.get("coverage_claim")
        run_class = scan.get("run_class")
        owner_deferred = scan.get("owner_deferred") is True
        if mode not in ("refresh", "reconcile", "onboard"):
            validator.error("quality scan mode is invalid")
        expected_claim = (
            "partial-cohort-owner-deferred-tail"
            if owner_deferred
            else (
                "partial-cohort-reconcile"
                if run_class == "phase8-cohort-a"
                else (
                    "complete-reconcile"
                    if mode == "reconcile"
                    else "bounded-run"
                )
            )
        )
        if (
            run_class not in (None, "phase8-cohort-a")
            or (
                run_class == "phase8-cohort-a"
                and mode != "reconcile"
            )
            or claim != expected_claim
        ):
            validator.error("quality scan coverage claim is invalid")
        if owner_deferred:
            hash_fields = (
                "deferred_task_keys_sha256",
                "deferred_repository_proof_sha256",
                "deferral_contract_sha256",
            )
            completed = scan.get("completed_repositories")
            deferred = scan.get("deferred_repositories")
            universe = scan.get("task_universe_repositories")
            if (
                run_class != "phase8-cohort-a"
                or mode != "reconcile"
                or any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                    for value in (completed, deferred, universe)
                )
                or deferred <= 0
                or completed + deferred != universe
                or any(
                    not isinstance(scan.get(field), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", scan[field])
                    for field in hash_fields
                )
            ):
                validator.error(
                    "quality scan owner-deferred tail is invalid"
                )
        integer_fields = (
            "selected_repositories",
            "files_examined",
            "bytes_examined",
            "skipped_large_files",
            "pruned_large_assets",
        )
        for field in integer_fields:
            value = scan.get(field)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                validator.error(f"quality scan {field} is invalid")
        if scan.get("policy") != SCAN_POLICY:
            validator.error("quality scan policy is invalid")
        if scan.get("freshness") != SCAN_FRESHNESS:
            validator.error("quality scan freshness is invalid")
        skipped = scan.get("skipped_large_files")
        if isinstance(skipped, int) and not isinstance(skipped, bool):
            if scan.get("complete") != (
                skipped == 0 and not owner_deferred
            ):
                validator.error(
                    "quality scan completeness does not reflect skipped files "
                    "or owner-deferred coverage"
                )
            if (
                mode == "reconcile"
                and scan.get("complete") is not True
                and not owner_deferred
            ):
                validator.error(
                    "full reconciliation cannot publish incomplete scan coverage"
                )
            if owner_deferred and scan.get("complete") is not False:
                validator.error(
                    "owner-deferred scan coverage must remain incomplete"
                )

    migration = quality.get("migration")
    if not isinstance(migration, Mapping):
        validator.error("quality migration must be an object")
        return
    mixed = migration.get("mixed_v1_v2")
    stale = migration.get("stale")
    carried = migration.get("carried_forward_library_ids")
    selected = migration.get("selected_library_ids")
    if not isinstance(mixed, bool) or not isinstance(stale, bool):
        validator.error("quality migration flags must be booleans")
    if not isinstance(carried, list) or not all(
        isinstance(value, str) for value in carried
    ):
        validator.error("quality carried-forward libraries must be a string list")
        carried = []
    if not isinstance(selected, list) or not all(
        isinstance(value, str) for value in selected
    ):
        validator.error("quality selected libraries must be a string list")
        selected = []
    if len(set(carried)) != len(carried) or list(carried) != sorted(carried):
        validator.error("quality carried-forward libraries are not unique/sorted")
    if len(set(selected)) != len(selected) or list(selected) != sorted(selected):
        validator.error("quality selected libraries are not unique/sorted")
    if not set(carried).issubset(library_ids) or not set(selected).issubset(
        library_ids
    ):
        validator.error("quality migration libraries are outside the manifest")
    if set(carried) & set(selected):
        validator.error("quality carried and selected libraries overlap")
    if mixed != bool(carried) or stale != bool(carried):
        validator.error("quality mixed/stale flags do not match carry-forward")


def validate_v2(
    root: str | os.PathLike[str],
    *,
    target_bytes: int = TARGET_ARTIFACT_BYTES,
    require_artifact_closure: bool = True,
) -> list[str]:
    """Return every publication error.  An empty list means release-ready."""
    root = Path(root)
    validator = _Validation(root, target_bytes)
    if root.is_symlink():
        validator.error("V2 root must not be a symlink")
        return validator.errors
    if root.exists():
        symlinks = [path for path in root.rglob("*") if path.is_symlink()]
        if symlinks:
            validator.error("V2 tree must not contain symlink artifacts")
            return validator.errors
    manifest = _manifest(root, validator)
    if manifest is None:
        return validator.errors
    release = manifest.get("release")
    if not isinstance(release, Mapping) or not isinstance(release.get("id"), str):
        validator.error("manifest release metadata is missing")
    elif release.get("source_visibility_attestation") not in (
        STATE_VISIBILITY_ATTESTATION,
        LEGACY_VISIBILITY_ATTESTATION,
    ):
        validator.error("manifest source visibility attestation is invalid")
    if not isinstance(manifest.get("generated_at"), str):
        validator.error("manifest generated_at must be a string")
    elif isinstance(release, Mapping) and release.get("generated_at") != manifest.get(
        "generated_at"
    ):
        validator.error("manifest and release generated_at differ")
    try:
        publication_day = datetime.date.fromisoformat(
            str(manifest.get("generated_at"))[:10]
        )
    except ValueError:
        publication_day = datetime.date.min
    if not isinstance(manifest.get("totals"), Mapping):
        validator.error("manifest totals must be an object")

    _quality_path, quality = validator.json_artifact(
        manifest.get("quality"), "quality artifact"
    )
    if isinstance(quality, Mapping) and quality.get("kind") != "quality":
        validator.error("quality artifact has wrong kind")
    if (
        isinstance(release, Mapping)
        and release.get("source_visibility_attestation")
        == LEGACY_VISIBILITY_ATTESTATION
    ):
        scan = quality.get("scan") if isinstance(quality, Mapping) else None
        discovery = (
            quality.get("discovery_stats")
            if isinstance(quality, Mapping)
            else None
        )
        if (
            not isinstance(scan, Mapping)
            or scan.get("evidence_kind") != "legacy-summary"
            or not isinstance(discovery, Mapping)
            or any(
                not isinstance(item, Mapping)
                or item.get("evidence_kind") not in (
                    "legacy-summary",
                    "carried-forward-v1",
                    "not-evaluated",
                )
                for item in discovery.values()
            )
        ):
            validator.error(
                "legacy visibility attestation requires migration-only "
                "legacy quality"
            )
    _delta_path, deltas = validator.json_artifact(
        manifest.get("deltas"), "deltas artifact"
    )
    if isinstance(deltas, Mapping) and deltas.get("kind") != "deltas":
        validator.error("deltas artifact has wrong kind")

    libraries = manifest.get("libraries")
    if not isinstance(libraries, list):
        validator.error("manifest libraries must be a list")
        return validator.errors
    manifest_cards = {
        card.get("id"): card
        for card in libraries
        if isinstance(card, Mapping) and isinstance(card.get("id"), str)
    }
    ids: set[str] = set()
    adoption_union: set[str] = set()
    portfolio_confirmed: set[str] = set()
    for card in libraries:
        if not isinstance(card, Mapping):
            validator.error("manifest contains a non-object library card")
            continue
        library_id = card.get("id")
        if not isinstance(library_id, str) or not library_id:
            validator.error("manifest library card is missing id")
            continue
        if library_id in ids:
            validator.error("manifest contains a duplicate library id")
            continue
        ids.add(library_id)
        _path, index = validator.json_artifact(
            card.get("index"), f"{library_id} library index"
        )
        if not isinstance(index, Mapping):
            continue
        if isinstance(card.get("index"), Mapping) and card["index"].get(
            "rows"
        ) != index.get("row_count"):
            validator.error(f"{library_id} index descriptor row count differs")
        if index.get("kind") != "library_index" or index.get("library_id") != library_id:
            validator.error(f"{library_id} index has wrong kind or library_id")
        if card.get("classification_coverage") != index.get(
            "classification_coverage"
        ):
            validator.error(f"{library_id} coverage differs between card and index")
        if card.get("discovery_coverage") != index.get(
            "discovery_coverage"
        ):
            validator.error(
                f"{library_id} discovery coverage differs between card and index"
            )
        citation_new_7d = card.get("citation_new_7d")
        if citation_new_7d is not None and (
            not isinstance(citation_new_7d, int) or citation_new_7d < 0
        ):
            validator.error(f"{library_id} seven-day paper count is invalid")
        measured, names, confirmed_names, new_repos_7d = _validate_repo_rows(
            validator, library_id, index, publication_day
        )
        if (
            card.get("new_repos_7d") != new_repos_7d
            or index.get("new_repos_7d") != new_repos_7d
        ):
            validator.error(
                f"{library_id} seven-day repository count does not reconcile"
            )
        adoption_union.update(names)
        portfolio_confirmed.update(confirmed_names)
        additive_children = []
        if card.get("component_rollup_mode") == "additive":
            if library_id != "nvpl":
                validator.error(
                    f"{library_id} illegally declares an additive component rollup"
                )
            additive_children = [
                child
                for child in manifest_cards.values()
                if child.get("parent_id") == library_id
                and child.get("is_component") is True
            ]
            declared_children = card.get("component_ids")
            if not additive_children or declared_children != sorted(
                child["id"] for child in additive_children
            ):
                validator.error(
                    f"{library_id} additive component set is missing or inconsistent"
                )
            if card.get("component_rollup_contract") != (
                "children_plus_unmapped_parent"
            ):
                validator.error(
                    f"{library_id} additive component contract is missing"
                )
            residual_counts = card.get("component_residual_counts")
            if not isinstance(residual_counts, Mapping) or any(
                not isinstance(residual_counts.get(classification), int)
                or residual_counts[classification] < 0
                for classification in CLASSIFICATIONS
            ):
                validator.error(
                    f"{library_id} additive residual counts are invalid"
                )
                residual_counts = {}
        else:
            residual_counts = {}
        for classification in CLASSIFICATIONS:
            field = f"{classification}_count"
            if additive_children:
                child_values = [child.get(field) for child in additive_children]
                expected_count = (
                    sum(child_values)
                    + int(residual_counts.get(classification) or 0)
                    if all(isinstance(value, int) for value in child_values)
                    else None
                )
            else:
                expected_count = (
                    measured[classification]
                    if (card.get("classification_coverage") or {}).get(classification)
                    == "evaluated"
                    else None
                )
            if card.get(field) != expected_count:
                basis = "components" if additive_children else "rows"
                validator.error(
                    f"{library_id} {field} does not reconcile to {basis}"
                )
        card_coverage = card.get("classification_coverage") or {}
        if additive_children:
            residual_headline = card.get("component_residual_headline_count")
            if not isinstance(residual_headline, int) or residual_headline < 0:
                validator.error(
                    f"{library_id} additive residual headline count is invalid"
                )
                residual_headline = 0
            child_headlines = [
                child.get("headline_count") for child in additive_children
            ]
            expected_headline = (
                sum(child_headlines)
                + residual_headline
                if all(isinstance(value, int) for value in child_headlines)
                else None
            )
        else:
            expected_headline = (
                measured["confirmed"]
                if card_coverage.get("confirmed") == "evaluated"
                else None
            )
            if (
                expected_headline is not None
                and card.get("adoption_counts_build")
            ):
                expected_headline = (
                    expected_headline + measured["bundled"]
                    if card_coverage.get("bundled") == "evaluated"
                    else None
                )
        if card.get("headline_count") != expected_headline:
            basis = "components" if additive_children else "rows"
            validator.error(
                f"{library_id} headline_count does not reconcile to {basis}"
            )
        citation_descriptor = card.get("citations_index")
        if citation_descriptor is not None:
            citation_index = _validate_citations(
                validator, library_id, citation_descriptor
            )
            if (
                isinstance(citation_index, Mapping)
                and card.get("citation_new_7d") != citation_index.get("new_7d")
            ):
                validator.error(
                    f"{library_id} seven-day paper count does not reconcile"
                )

    if (
        isinstance(release, Mapping)
        and release.get("scope") == "partial-portfolio"
    ):
        coverage = manifest.get("portfolio_coverage")
        if (
            release.get("label") != "Phase 8 Cohort A"
            or release.get("run_class") != "phase8-cohort-a"
            or release.get("portfolio_complete") is not False
        ):
            validator.error(
                "partial cohort release metadata is not explicit"
            )
        if not isinstance(coverage, Mapping):
            validator.error(
                "partial cohort release lacks portfolio coverage metadata"
            )
            coverage = {}
        selected = coverage.get("selected_library_ids")
        excluded = coverage.get("excluded_library_ids")
        if not isinstance(selected, list) or not all(
            isinstance(value, str) for value in selected
        ):
            validator.error(
                "partial cohort selected libraries must be a string list"
            )
            selected = []
        if not isinstance(excluded, list) or not all(
            isinstance(value, str) for value in excluded
        ):
            validator.error(
                "partial cohort excluded libraries must be a string list"
            )
            excluded = []
        if (
            selected != sorted(set(selected))
            or excluded != sorted(set(excluded))
            or set(selected) & set(excluded)
            or not (set(selected) | set(excluded)).issubset(ids)
        ):
            validator.error(
                "partial cohort selected/excluded scope is inconsistent"
            )
        cards_by_id = {
            card.get("id"): card
            for card in libraries
            if isinstance(card, Mapping)
        }
        for library_id in selected:
            if cards_by_id.get(library_id, {}).get(
                "collection_status"
            ) != "collected":
                validator.error(
                    f"{library_id} selected cohort card is not collected"
                )
        for library_id in excluded:
            card = cards_by_id.get(library_id, {})
            card_coverage = card.get("classification_coverage") or {}
            if (
                card.get("collection_status") != "not_collected"
                or any(
                    card_coverage.get(classification)
                    != "not_evaluated"
                    for classification in CLASSIFICATIONS
                )
                or any(
                    card.get(f"{classification}_count") is not None
                    for classification in CLASSIFICATIONS
                )
                or card.get("headline_count") is not None
            ):
                validator.error(
                    f"{library_id} excluded cohort card is not explicitly "
                    "not collected"
                )
        migration = (
            quality.get("migration")
            if isinstance(quality, Mapping)
            else {}
        )
        if (
            not isinstance(migration, Mapping)
            or migration.get("selected_library_ids") != selected
        ):
            validator.error(
                "partial cohort scope differs from migration quality"
            )

    export_names = _validate_exports(validator, manifest.get("exports"))
    if export_names != adoption_union:
        validator.error("repository exports do not match library-shard membership")
    total = (manifest.get("totals") or {}).get("confirmed_integrator_repos")
    if total != len(portfolio_confirmed):
        validator.error(
            "portfolio confirmed_integrator_repos does not reconcile to repository rows"
        )
    if isinstance(quality, Mapping):
        _validate_discovery_quality(validator, quality, ids)
        _validate_scan_and_migration_quality(
            validator, quality, ids
        )
    if isinstance(release, Mapping):
        expected_release = _release_identity(manifest)
        if release.get("id") != expected_release:
            validator.error("release id does not match manifest semantics")
    if require_artifact_closure:
        actual_files = {
            path.relative_to(validator.root).as_posix()
            for path in validator.root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        expected_files = {"manifest.json", *validator.paths}
        if actual_files != expected_files:
            validator.error(
                "V2 tree contains unreferenced or unindexed artifact files"
            )
    return validator.errors


def _v2_library_rows(root: Path, card: Mapping[str, Any]) -> tuple[dict, list[dict]]:
    index = _load_json(root / card["index"]["path"])
    rows = []
    for descriptor in index["repo_parts"]:
        rows.extend(_load_json(root / descriptor["path"])["rows"])
    return index, rows


def compare_v1_v2(
    current: Mapping[str, Any],
    timeseries: Mapping[str, Any] | None,
    citations: Mapping[str, Any] | None,
    v2_root: str | os.PathLike[str],
    deltas: Mapping[str, Any] | None = None,
) -> list[str]:
    """Compare all semantic V1 fields that V2 promises to preserve."""
    root = Path(v2_root)
    errors = validate_v2(root)
    if errors:
        return errors
    manifest = _load_json(root / "manifest.json")
    cards = {card["id"]: card for card in manifest["libraries"]}
    source_cards = {card["id"]: card for card in current.get("libraries", [])}
    if set(cards) != set(source_cards):
        errors.append("V1/V2 library membership differs")
        return errors

    for library_id, source_card in source_cards.items():
        card = cards[library_id]
        for field in (
            "confirmed_count",
            "bundled_count",
            "targeted_count",
            "headline_count",
            "delta_since_last",
            "sparkline",
            "sparkline_months",
        ):
            classification = field.removesuffix("_count")
            if (
                field.endswith("_count")
                and (card.get("classification_coverage") or {}).get(classification)
                == "not_evaluated"
            ):
                if card.get(field) is not None:
                    errors.append(f"V1/V2 {library_id} {field} must be not evaluated")
                continue
            if card.get(field) != source_card.get(field):
                errors.append(f"V1/V2 {library_id} {field} differs")
        index, rows = _v2_library_rows(root, card)
        if index.get("timeseries") != (timeseries or {}).get(library_id, {}):
            errors.append(f"V1/V2 {library_id} timeseries differs")
        expected = {}
        for repo in current.get("repos", []):
            entry = _effective_entry(repo, source_card)
            if entry is not None:
                expected[repo.get("full_name")] = (
                    entry.get("classification"),
                    entry.get("first_integration"),
                    entry.get("first_integration_commit"),
                )
        actual = {}
        for row in rows:
            entry = row["libraries"][0]
            actual[row["full_name"]] = (
                entry.get("classification"),
                entry.get("first_integration"),
                entry.get("first_integration_commit"),
            )
        if actual != expected:
            errors.append(f"V1/V2 {library_id} repo membership/evidence differs")

    citation_source = (citations or {}).get("libraries") or {}
    for library_id, source in citation_source.items():
        card = cards.get(library_id)
        if not card or not card.get("citations_index"):
            errors.append(f"V1/V2 {library_id} citations are missing")
            continue
        index = _load_json(root / card["citations_index"]["path"])
        papers = []
        for part in index["paper_parts"]:
            papers.extend(_load_json(root / part["path"])["rows"])
        expected = sorted(
            source.get("papers") or [],
            key=lambda paper: (
                str(paper.get("publication_date") or ""),
                str(paper.get("doi") or ""),
                str(paper.get("title") or ""),
            ),
        )
        if papers != expected:
            errors.append(f"V1/V2 {library_id} citation papers differ")
        for field in (
            "total",
            "new_since_last",
            "new_7d",
            "monthly",
            "growth_90d",
            "growth_365d",
            "papers_capped",
            "repo_papers",
        ):
            if index.get(field) != source.get(field):
                errors.append(f"V1/V2 {library_id} citation {field} differs")

    delta_document = _load_json(root / manifest["deltas"]["path"])
    expected_deltas = dict(deltas or {})
    expected_deltas["schema_version"] = "2.0"
    expected_deltas["kind"] = "deltas"
    if delta_document != expected_deltas:
        errors.append("V1/V2 deltas differ")

    # Export rows are a consumer contract in their own right. The universal
    # validator proves cross-format membership; parity additionally proves that
    # the exported JSONL fields are the exact V1 projection.
    from .publish_v2 import _export_repo_row

    export_index = _load_json(root / manifest["exports"]["path"])
    exported = []
    for descriptor in export_index["jsonl_parts"]:
        payload = (root / descriptor["path"]).read_text()
        exported.extend(
            json.loads(line)
            for line in payload.splitlines()
            if line
        )
    expected_exports = sorted(
        (_export_repo_row(repo) for repo in current.get("repos", [])),
        key=lambda row: str(row.get("full_name") or "").casefold(),
    )
    if exported != expected_exports:
        errors.append("V1/V2 repository exports differ")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate all manifest-driven V2 publication artifacts"
    )
    parser.add_argument("root", nargs="?", default="data/v2")
    parser.add_argument("--target-bytes", type=int, default=TARGET_ARTIFACT_BYTES)
    parser.add_argument("--v1-data-dir")
    args = parser.parse_args(argv)
    errors = validate_v2(args.root, target_bytes=args.target_bytes)
    if not errors and args.v1_data_dir:
        data = Path(args.v1_data_dir)
        errors.extend(
            compare_v1_v2(
                _load_json(data / "current.json"),
                _load_json(data / "timeseries.json"),
                _load_json(data / "citations.json")
                if (data / "citations.json").exists()
                else {},
                args.root,
                _load_json(data / "deltas.json")
                if (data / "deltas.json").exists()
                else {},
            )
        )
    if errors:
        for error in errors:
            print("ERROR: " + error)
        print(f"V2 validation FAILED ({len(errors)} error(s))")
        return 1
    print("V2 validation PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
